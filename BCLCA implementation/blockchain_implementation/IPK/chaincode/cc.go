package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
)

const (
	docTypeIPK    = "ipk"
	statusActive  = "ACTIVE"
	statusRevoked = "REVOKED"
)

var authorizedKGCMSPs = map[string]struct{}{
	"EastChinaMSP":  {},
	"NorthChinaMSP": {},
	"AirChinaMSP":   {},
	"CsairMSP":      {},
}

// Atc keeps its historical name to avoid changing the existing service API.
// It now represents the lightweight on-chain metadata of an IPK credential.
type Atc struct {
	DocType          string `json:"docType"`
	ID               string `json:"ID"`
	ASID             string `json:"ASID"`
	KGCID            string `json:"KGCID"`
	CID              string `json:"CID"`
	CredentialHash   string `json:"CredentialHash"`
	Signature        string `json:"Signature"`
	IssuedAt         int64  `json:"IssuedAt"`
	ValidFrom        int64  `json:"ValidFrom"`
	ValidUntil       int64  `json:"ValidUntil"`
	Status           string `json:"Status"`
	Version          uint64 `json:"Version"`
	UpdatedAt        int64  `json:"UpdatedAt,omitempty"`
	RevokedAt        int64  `json:"RevokedAt,omitempty"`
	RevocationReason string `json:"RevocationReason,omitempty"`

	Historys []HistoryItem `json:"Historys,omitempty"`
}

type HistoryItem struct {
	TxId string `json:"TxId"`
	Atc  Atc    `json:"Atc"`
}

type AtcChaincode struct{}

func (t *AtcChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	fmt.Print("=========== Init IPK chaincode ===========")
	return shim.Success(nil)
}

func (t *AtcChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fun, args := stub.GetFunctionAndParameters()

	switch fun {
	case "addAtc":
		return t.addAtc(stub, args)
	case "queryAtcInfoByID":
		return t.queryAtcInfoByID(stub, args)
	case "queryAtcByQueryString":
		return t.queryAtcByQueryString(stub, args)
	case "updateAtc":
		return t.updateAtc(stub, args)
	case "delAtc":
		return t.delAtc(stub, args)
	default:
		return shim.Error("unsupported chaincode function")
	}
}

// addAtc publishes the first ACTIVE IPK credential for an AS/KGC pair.
func (t *AtcChaincode) addAtc(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("expected IPK metadata and event ID")
	}

	var atc Atc
	if err := json.Unmarshal([]byte(args[0]), &atc); err != nil {
		return shim.Error("invalid IPK metadata: " + err.Error())
	}

	mspID, err := authorizedKGC(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	now, err := transactionTime(stub)
	if err != nil {
		return shim.Error(err.Error())
	}

	atc.DocType = docTypeIPK
	atc.KGCID = mspID
	atc.ID = ipkKey(atc.ASID, atc.KGCID)
	atc.IssuedAt = now
	atc.UpdatedAt = now
	if atc.ValidFrom == 0 {
		atc.ValidFrom = now
	}
	atc.Status = statusActive
	atc.Version = 1
	atc.RevokedAt = 0
	atc.RevocationReason = ""
	atc.Historys = nil

	if err := validateIPK(atc); err != nil {
		return shim.Error(err.Error())
	}
	existing, err := stub.GetState(atc.ID)
	if err != nil {
		return shim.Error("failed to check existing IPK: " + err.Error())
	}
	if existing != nil {
		return shim.Error("IPK already exists; use updateAtc for key rotation")
	}

	if _, ok := PutAtc(stub, atc); !ok {
		return shim.Error("failed to save IPK metadata")
	}
	if err := stub.SetEvent(args[1], []byte(atc.ID)); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success([]byte(atc.ID))
}

func (t *AtcChaincode) queryAtcInfoByID(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 1 {
		return shim.Error("expected IPK ID")
	}

	atc, ok := GetAtcInfo(stub, args[0])
	if !ok {
		return shim.Error("IPK not found")
	}
	items, err := getHistory(stub, atc.ID)
	if err != nil {
		return shim.Error("failed to read IPK history: " + err.Error())
	}
	atc.Historys = *items

	result, err := json.Marshal(atc)
	if err != nil {
		return shim.Error("failed to serialize IPK: " + err.Error())
	}
	return shim.Success(result)
}

func getHistory(stub shim.ChaincodeStubInterface, atcID string) (*[]HistoryItem, error) {
	iterator, err := stub.GetHistoryForKey(atcID)
	if err != nil {
		return nil, err
	}
	defer iterator.Close()

	historys := make([]HistoryItem, 0)
	for iterator.HasNext() {
		historyData, err := iterator.Next()
		if err != nil {
			return nil, err
		}
		item := HistoryItem{TxId: historyData.TxId}
		if historyData.Value != nil {
			if err := json.Unmarshal(historyData.Value, &item.Atc); err != nil {
				return nil, err
			}
		}
		historys = append(historys, item)
	}
	return &historys, nil
}

// queryAtcByQueryString accepts a JSON object containing only ASID and/or
// KGCID. Revoked and expired credentials are always excluded.
func (t *AtcChaincode) queryAtcByQueryString(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 1 {
		return shim.Error("expected IPK query criteria")
	}

	criteria := make(map[string]string)
	if strings.TrimSpace(args[0]) != "" && strings.TrimSpace(args[0]) != "{}" {
		if err := json.Unmarshal([]byte(args[0]), &criteria); err != nil {
			return shim.Error("query criteria must be a JSON object: " + err.Error())
		}
	}
	for field := range criteria {
		if field != "ASID" && field != "KGCID" {
			return shim.Error("only ASID and KGCID can be queried")
		}
	}

	now, err := transactionTime(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	selector := map[string]interface{}{
		"docType":    docTypeIPK,
		"Status":     statusActive,
		"ValidFrom":  map[string]int64{"$lte": now},
		"ValidUntil": map[string]int64{"$gte": now},
	}
	for field, value := range criteria {
		if strings.TrimSpace(value) != "" {
			selector[field] = strings.TrimSpace(value)
		}
	}
	queryBytes, err := json.Marshal(map[string]interface{}{"selector": selector})
	if err != nil {
		return shim.Error("failed to build IPK query: " + err.Error())
	}

	resultsIterator, err := stub.GetQueryResult(string(queryBytes))
	if err != nil {
		return shim.Error("failed to query IPKs: " + err.Error())
	}
	defer resultsIterator.Close()

	atcs := make([]Atc, 0)
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return shim.Error("failed to read IPK query result: " + err.Error())
		}
		var atc Atc
		if err := json.Unmarshal(queryResponse.Value, &atc); err != nil {
			return shim.Error("failed to decode IPK query result: " + err.Error())
		}
		atcs = append(atcs, atc)
	}

	data, err := json.Marshal(atcs)
	if err != nil {
		return shim.Error("failed to serialize IPK query result: " + err.Error())
	}
	return shim.Success(data)
}

// updateAtc rotates an IPK while preserving previous versions in ledger history.
func (t *AtcChaincode) updateAtc(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("expected IPK metadata and event ID")
	}

	var input Atc
	if err := json.Unmarshal([]byte(args[0]), &input); err != nil {
		return shim.Error("invalid IPK metadata: " + err.Error())
	}
	mspID, err := authorizedKGC(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	if input.ID == "" {
		input.ID = ipkKey(input.ASID, mspID)
	}

	current, ok := GetAtcInfo(stub, input.ID)
	if !ok {
		return shim.Error("IPK not found")
	}
	if current.KGCID != mspID {
		return shim.Error("only the issuing KGC can rotate this IPK")
	}
	if input.ASID != "" && input.ASID != current.ASID {
		return shim.Error("ASID cannot be changed")
	}
	if input.KGCID != "" && input.KGCID != current.KGCID {
		return shim.Error("KGCID cannot be changed")
	}

	now, err := transactionTime(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	current.CID = input.CID
	current.CredentialHash = input.CredentialHash
	current.Signature = input.Signature
	current.ValidFrom = input.ValidFrom
	if current.ValidFrom == 0 {
		current.ValidFrom = now
	}
	current.ValidUntil = input.ValidUntil
	current.IssuedAt = now
	current.UpdatedAt = now
	current.Status = statusActive
	current.Version++
	current.RevokedAt = 0
	current.RevocationReason = ""
	current.Historys = nil

	if err := validateIPK(current); err != nil {
		return shim.Error(err.Error())
	}
	if _, ok := PutAtc(stub, current); !ok {
		return shim.Error("failed to save rotated IPK")
	}
	if err := stub.SetEvent(args[1], []byte(current.ID)); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success([]byte(current.ID))
}

// delAtc performs a logical revocation so the audit trail remains available.
func (t *AtcChaincode) delAtc(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("expected IPK ID and event ID")
	}

	mspID, err := authorizedKGC(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	atc, ok := GetAtcInfo(stub, args[0])
	if !ok {
		return shim.Error("IPK not found")
	}
	if atc.KGCID != mspID {
		return shim.Error("only the issuing KGC can revoke this IPK")
	}
	if atc.Status == statusRevoked {
		return shim.Error("IPK is already revoked")
	}

	now, err := transactionTime(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	atc.Status = statusRevoked
	atc.RevokedAt = now
	atc.UpdatedAt = now
	atc.RevocationReason = "revoked by issuing KGC"
	atc.Historys = nil

	if _, ok := PutAtc(stub, atc); !ok {
		return shim.Error("failed to revoke IPK")
	}
	if err := stub.SetEvent(args[1], []byte(atc.ID)); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success([]byte(atc.ID))
}

func PutAtc(stub shim.ChaincodeStubInterface, atc Atc) ([]byte, bool) {
	atc.Historys = nil
	b, err := json.Marshal(atc)
	if err != nil {
		return nil, false
	}
	if err := stub.PutState(atc.ID, b); err != nil {
		return nil, false
	}
	return b, true
}

func GetAtcInfo(stub shim.ChaincodeStubInterface, ID string) (Atc, bool) {
	var atc Atc
	b, err := stub.GetState(ID)
	if err != nil || b == nil {
		return atc, false
	}
	if err := json.Unmarshal(b, &atc); err != nil {
		return Atc{}, false
	}
	return atc, true
}

func authorizedKGC(stub shim.ChaincodeStubInterface) (string, error) {
	creator, err := stub.GetCreator()
	if err != nil {
		return "", fmt.Errorf("failed to identify invoking organization: %v", err)
	}
	identity := &msp.SerializedIdentity{}
	if err := proto.Unmarshal(creator, identity); err != nil {
		return "", fmt.Errorf("failed to decode invoking identity: %v", err)
	}
	mspID := identity.Mspid
	if _, ok := authorizedKGCMSPs[mspID]; !ok {
		return "", fmt.Errorf("organization %s is not an authorized KGC", mspID)
	}
	return mspID, nil
}

func transactionTime(stub shim.ChaincodeStubInterface) (int64, error) {
	timestamp, err := stub.GetTxTimestamp()
	if err != nil {
		return 0, fmt.Errorf("failed to obtain transaction timestamp: %v", err)
	}
	return timestamp.Seconds, nil
}

func ipkKey(asID, kgcID string) string {
	return "ipk:" + url.QueryEscape(strings.TrimSpace(asID)) + ":" + url.QueryEscape(strings.TrimSpace(kgcID))
}

func validateIPK(atc Atc) error {
	if strings.TrimSpace(atc.ASID) == "" {
		return fmt.Errorf("ASID is required")
	}
	if strings.TrimSpace(atc.KGCID) == "" {
		return fmt.Errorf("KGCID is required")
	}
	if strings.TrimSpace(atc.CID) == "" {
		return fmt.Errorf("IPFS CID is required")
	}
	if strings.TrimSpace(atc.CredentialHash) == "" {
		return fmt.Errorf("credential hash is required")
	}
	if strings.TrimSpace(atc.Signature) == "" {
		return fmt.Errorf("KGC signature is required")
	}
	if atc.ValidFrom <= 0 || atc.ValidUntil <= 0 || atc.ValidUntil <= atc.ValidFrom {
		return fmt.Errorf("IPK validity period is invalid")
	}
	if atc.Status != statusActive && atc.Status != statusRevoked {
		return fmt.Errorf("invalid IPK status")
	}
	return nil
}

func main() {
	if err := shim.Start(new(AtcChaincode)); err != nil {
		fmt.Printf("failed to start IPK chaincode: %s", err)
	}
}

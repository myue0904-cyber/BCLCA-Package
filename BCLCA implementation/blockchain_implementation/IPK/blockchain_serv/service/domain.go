package service

import (
	"encoding/json"
	"fmt"
	"log"
	"sdk"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

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

type ReturnHistoryItem struct {
	IssuedAt       int64  `json:"IssuedAt"`
	CID            string `json:"CID"`
	CredentialHash string `json:"CredentialHash"`
	Status         string `json:"Status"`
	Version        uint64 `json:"Version"`
}

type ServiceSetup struct {
	ChaincodeID   string
	ChannelClient *channel.Client
	LedgerClient  *ledger.Client
}

var (
	info   sdk.SdkEnvInfo
	logger *log.Logger
)

func init() {
	cc_name := "atc_chaincode"
	cc_version := "1.1.0"

	orgs := []*sdk.OrgInfo{
		{
			OrgAdminUser:  "Admin",
			OrgName:       "EastChina",
			OrgMspId:      "EastChinaMSP",
			OrgUser:       "User1",
			OrgPeerNum:    1,
			OrgAnchorFile: "/root/go/src/atc/fabric/channel-artifacts/EastChinaMSPanchors.tx",
		},
		{
			OrgAdminUser:  "Admin",
			OrgName:       "NorthChina",
			OrgMspId:      "NorthChinaMSP",
			OrgUser:       "User1",
			OrgPeerNum:    1,
			OrgAnchorFile: "/root/go/src/atc/fabric/channel-artifacts/NorthChinaMSPanchors.tx",
		},
		{
			OrgAdminUser:  "Admin",
			OrgName:       "AirChina",
			OrgMspId:      "AirChinaMSP",
			OrgUser:       "User1",
			OrgPeerNum:    1,
			OrgAnchorFile: "/root/go/src/atc/fabric/channel-artifacts/AirChinaMSPanchors.tx",
		},
		{
			OrgAdminUser:  "Admin",
			OrgName:       "Csair",
			OrgMspId:      "CsairMSP",
			OrgUser:       "User1",
			OrgPeerNum:    1,
			OrgAnchorFile: "/root/go/src/atc/fabric/channel-artifacts/CsairMSPanchors.tx",
		},
	}

	info = sdk.SdkEnvInfo{
		ChannelID:        "mychannel",
		ChannelConfig:    "/root/go/src/atc/fabric/channel-artifacts/mychannel.block",
		Orgs:             orgs,
		OrdererAdminUser: "Admin",
		OrdererOrgName:   "ATCOrderer",
		OrdererEndpoint:  "orderer.atc.com",
		ChaincodeID:      cc_name,
		ChaincodePath:    "/home/jiaxv/research/atc/IPK/chaincode/",
		ChaincodeVersion: cc_version,
	}

	logger = logs.GetLogger()
}

func RegitserEvent(client *channel.Client, chaincodeID, eventID string) (fab.Registration, <-chan *fab.CCEvent) {

	reg, notifier, err := client.RegisterChaincodeEvent(chaincodeID, eventID)
	if err != nil {
		fmt.Println("注册链码事件失败:", err)
	}
	return reg, notifier
}

func EventResult(notifier <-chan *fab.CCEvent, eventID string) error {
	select {
	case ccEvent := <-notifier:
		fmt.Printf("接收到链码事件: %v\n", ccEvent)
	case <-time.After(time.Second * 20):
		return fmt.Errorf("不能根据指定的事件ID接收到相应的链码事件(%s)", eventID)
	}
	return nil
}

func InitService(chaincodeID, channelID string, org *sdk.OrgInfo, sdk *fabsdk.FabricSDK) (*ServiceSetup, error) {
	handler := &ServiceSetup{
		ChaincodeID: chaincodeID,
	}
	clientChannelContext := sdk.ChannelContext(channelID, fabsdk.WithUser(org.OrgUser), fabsdk.WithOrg(org.OrgName))
	channel_client, err := channel.New(clientChannelContext)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new channel client: %s", err)
	}
	ledger_client, err := ledger.New(clientChannelContext)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new ledger client: %s", err)
	}

	handler.ChannelClient = channel_client
	handler.LedgerClient = ledger_client
	return handler, nil
}

func InitSetup(configpath, company string) *ServiceSetup {
	sdkentity, err := sdk.Setup(configpath, &info)

	num := getOrgNum(company)

	if num < 0 {
		return nil
	}

	if err != nil {
		logger.Println(">> Sdk set error", err)
		return nil
	}

	servicesetup, err := InitService(info.ChaincodeID, info.ChannelID, info.Orgs[num], sdkentity)
	if err != nil {
		logger.Println(">> init chaincode error", err)
		return nil
	}

	return servicesetup
}

func getOrgNum(company string) int {
	for index, org := range info.Orgs {
		if strings.EqualFold(org.OrgName, company) {
			return index
		}
	}
	return -1
}

func Save(servicesetup *ServiceSetup, atc Atc) (string, error) {
	if err := validateIPKInput(atc); err != nil {
		return "", err
	}
	msg, err := servicesetup.SaveAtc(atc)
	if err != nil {
		logger.Println(err.Error())
		return "", err
	}
	logger.Println("信息发布成功, 交易编号为: " + msg)
	return msg, nil
}

func QueryByString(servicesetup *ServiceSetup, querystr string) *[]Atc {
	result, err := servicesetup.FindAtcByQueryString(querystr)

	var atcs []Atc
	if err != nil {
		fmt.Println(err.Error())
		return nil
	} else {
		if err := json.Unmarshal(result, &atcs); err != nil {
			logger.Println("IPK query result decode failed:", err)
			return nil
		}
		return &atcs
	}
}

func Modify(servicesetup *ServiceSetup, atc Atc) (string, error) {
	if err := validateIPKInput(atc); err != nil {
		return "", err
	}
	transid, err := servicesetup.ModifyAtc(atc)
	if err != nil {
		logger.Println(err.Error())
		return "", err
	}
	logger.Println("信息修改成功, 交易编号为: " + transid)

	return transid, nil
}

func Delete(servicesetup *ServiceSetup, ID string) (string, error) {
	if strings.TrimSpace(ID) == "" {
		return "", fmt.Errorf("IPK ID is required")
	}
	transid, err := servicesetup.DeleteAtc(ID)
	if err != nil {
		logger.Println(err.Error())
		return "", err
	}
	logger.Println("IPK撤销成功, 交易编号为: " + transid)

	return transid, nil
}

// validateIPKInput validates the off-chain metadata before it is submitted.
// KGCID, ID, status, timestamps and version are assigned by chaincode.
func validateIPKInput(atc Atc) error {
	if strings.TrimSpace(atc.ASID) == "" {
		return fmt.Errorf("ASID is required")
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
	if atc.ValidFrom < 0 || atc.ValidUntil <= 0 || atc.ValidUntil <= atc.ValidFrom {
		return fmt.Errorf("IPK validity period is invalid")
	}
	return nil
}

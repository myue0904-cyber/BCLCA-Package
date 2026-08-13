package service

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
)

func (t *ServiceSetup) SaveAtc(atc_info Atc) (string, error) {
	eventID := "eventAddAtc"
	reg, notifier := RegitserEvent(t.ChannelClient, t.ChaincodeID, eventID)
	defer t.ChannelClient.UnregisterChaincodeEvent(reg)

	if err := validateIPKInput(atc_info); err != nil {
		return "", err
	}

	// Serialize the IPK metadata submitted to chaincode.
	b, err := json.Marshal(atc_info)
	if err != nil {
		return "", fmt.Errorf("failed to serialize IPK metadata: %v", err)
	}

	logger.Println(string(b))

	req := channel.Request{ChaincodeID: t.ChaincodeID, Fcn: "addAtc", Args: [][]byte{b, []byte(eventID)}}
	respone, err := t.ChannelClient.Execute(req)
	if err != nil {
		return "", err
	}

	err = EventResult(notifier, eventID)
	if err != nil {
		return "", err
	}

	return string(respone.TransactionID), nil
}

func (t *ServiceSetup) FindAtcInfoByID(entityID string) ([]byte, error) {

	req := channel.Request{ChaincodeID: t.ChaincodeID, Fcn: "queryAtcInfoByID", Args: [][]byte{[]byte(entityID)}}
	respone, err := t.ChannelClient.Query(req)
	if err != nil {
		return []byte{0x00}, err
	}

	return respone.Payload, nil
}

func (t *ServiceSetup) FindAtcByQueryString(qs string) ([]byte, error) {
	req := channel.Request{ChaincodeID: t.ChaincodeID, Fcn: "queryAtcByQueryString", Args: [][]byte{[]byte(qs)}}

	respone, err := t.ChannelClient.Query(req)
	if err != nil {
		return []byte{0x00}, err
	}

	return respone.Payload, nil
}

func (t *ServiceSetup) ModifyAtc(atc_info Atc) (string, error) {

	eventID := "eventModifyAtc"
	reg, notifier := RegitserEvent(t.ChannelClient, t.ChaincodeID, eventID)
	defer t.ChannelClient.UnregisterChaincodeEvent(reg)

	if err := validateIPKInput(atc_info); err != nil {
		return "", err
	}

	// Serialize the rotated IPK metadata submitted to chaincode.
	b, err := json.Marshal(atc_info)
	if err != nil {
		return "", fmt.Errorf("failed to serialize IPK metadata: %v", err)
	}

	req := channel.Request{ChaincodeID: t.ChaincodeID, Fcn: "updateAtc", Args: [][]byte{b, []byte(eventID)}}
	respone, err := t.ChannelClient.Execute(req)
	if err != nil {
		return "", err
	}

	err = EventResult(notifier, eventID)
	if err != nil {
		return "", err
	}

	return string(respone.TransactionID), nil
}

func (t *ServiceSetup) DeleteAtc(ID string) (string, error) {

	eventID := "eventDelAtc"
	reg, notifier := RegitserEvent(t.ChannelClient, t.ChaincodeID, eventID)
	defer t.ChannelClient.UnregisterChaincodeEvent(reg)

	req := channel.Request{ChaincodeID: t.ChaincodeID, Fcn: "delAtc", Args: [][]byte{[]byte(ID), []byte(eventID)}}
	respone, err := t.ChannelClient.Execute(req)
	if err != nil {
		return "", err
	}

	err = EventResult(notifier, eventID)
	if err != nil {
		return "", err
	}

	return string(respone.TransactionID), nil
}

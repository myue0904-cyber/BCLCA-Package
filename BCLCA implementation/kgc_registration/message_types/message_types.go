package message_types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"gocode/kgc_registration/hash_utils"
)

const (
	MSG_REG_RQST = 1
	MSG_REG_RESP = 2
	MSG_UPLOAD   = 3
)

type RegRqstMsg struct {
	Type   uint8
	Entity string
	Nonce  []byte
	M1     []byte
}

type RegRespMsg struct {
	Type   uint8
	Entity string
	Nonce  []byte
	PPub   []byte
	Y      *big.Int
	R      []byte
}

type UploadMsg struct {
	Type   uint8
	Entity string
	Nonce  []byte
	UA     []byte
	X      []byte
	Y      []byte
}

func (msg *RegRqstMsg) Serialize() []byte {
	var buf bytes.Buffer

	buf.WriteByte(msg.Type)

	entityBytes := []byte(msg.Entity)
	buf.WriteByte(uint8(len(entityBytes)))
	buf.Write(entityBytes)

	buf.Write(msg.Nonce)

	binary.Write(&buf, binary.BigEndian, uint16(len(msg.M1)))
	buf.Write(msg.M1)

	return buf.Bytes()
}

func DeserializeRegRqst(data []byte) (*RegRqstMsg, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("数据太短")
	}

	reader := bytes.NewReader(data)
	msg := &RegRqstMsg{}

	if err := binary.Read(reader, binary.BigEndian, &msg.Type); err != nil {
		return nil, err
	}

	var entityLen uint8
	if err := binary.Read(reader, binary.BigEndian, &entityLen); err != nil {
		return nil, err
	}

	entityBytes := make([]byte, entityLen)
	if _, err := reader.Read(entityBytes); err != nil {
		return nil, err
	}
	msg.Entity = string(entityBytes)

	msg.Nonce = make([]byte, 16)
	if _, err := reader.Read(msg.Nonce); err != nil {
		return nil, err
	}

	var m1Len uint16
	if err := binary.Read(reader, binary.BigEndian, &m1Len); err != nil {
		return nil, err
	}

	msg.M1 = make([]byte, m1Len)
	if _, err := reader.Read(msg.M1); err != nil {
		return nil, err
	}

	return msg, nil
}

func (msg *RegRespMsg) Serialize() []byte {
	var buf bytes.Buffer

	buf.WriteByte(msg.Type)

	entityBytes := []byte(msg.Entity)
	buf.WriteByte(uint8(len(entityBytes)))
	buf.Write(entityBytes)

	buf.Write(msg.Nonce)

	buf.Write(msg.PPub)

	yBytes := hash_utils.BigIntToBytes32(msg.Y)
	buf.Write(yBytes)

	buf.Write(msg.R)

	return buf.Bytes()
}

func DeserializeRegResp(data []byte) (*RegRespMsg, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("数据太短")
	}

	reader := bytes.NewReader(data)
	msg := &RegRespMsg{}

	if err := binary.Read(reader, binary.BigEndian, &msg.Type); err != nil {
		return nil, err
	}

	var entityLen uint8
	if err := binary.Read(reader, binary.BigEndian, &entityLen); err != nil {
		return nil, err
	}

	entityBytes := make([]byte, entityLen)
	if _, err := reader.Read(entityBytes); err != nil {
		return nil, err
	}
	msg.Entity = string(entityBytes)

	msg.Nonce = make([]byte, 16)
	if _, err := reader.Read(msg.Nonce); err != nil {
		return nil, err
	}

	msg.PPub = make([]byte, 33)
	if _, err := reader.Read(msg.PPub); err != nil {
		return nil, err
	}

	yBytes := make([]byte, 32)
	if _, err := reader.Read(yBytes); err != nil {
		return nil, err
	}
	msg.Y = new(big.Int).SetBytes(yBytes)

	msg.R = make([]byte, 33)
	if _, err := reader.Read(msg.R); err != nil {
		return nil, err
	}

	return msg, nil
}

func (msg *UploadMsg) Serialize() []byte {
	var buf bytes.Buffer

	buf.WriteByte(msg.Type)

	entityBytes := []byte(msg.Entity)
	buf.WriteByte(uint8(len(entityBytes)))
	buf.Write(entityBytes)

	buf.Write(msg.Nonce)

	buf.Write(msg.UA)

	buf.Write(msg.X)

	buf.Write(msg.Y)

	return buf.Bytes()
}

func DeserializeUpload(data []byte) (*UploadMsg, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("数据太短")
	}

	reader := bytes.NewReader(data)
	msg := &UploadMsg{}

	if err := binary.Read(reader, binary.BigEndian, &msg.Type); err != nil {
		return nil, err
	}

	var entityLen uint8
	if err := binary.Read(reader, binary.BigEndian, &entityLen); err != nil {
		return nil, err
	}

	entityBytes := make([]byte, entityLen)
	if _, err := reader.Read(entityBytes); err != nil {
		return nil, err
	}
	msg.Entity = string(entityBytes)

	msg.Nonce = make([]byte, 16)
	if _, err := reader.Read(msg.Nonce); err != nil {
		return nil, err
	}

	msg.UA = make([]byte, 4)
	if _, err := reader.Read(msg.UA); err != nil {
		return nil, err
	}

	msg.X = make([]byte, 33)
	if _, err := reader.Read(msg.X); err != nil {
		return nil, err
	}

	msg.Y = make([]byte, 33)
	if _, err := reader.Read(msg.Y); err != nil {
		return nil, err
	}

	return msg, nil
}
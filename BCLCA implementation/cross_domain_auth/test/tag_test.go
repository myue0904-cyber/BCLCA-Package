package test

import (
	"github.com/hdt3213/godis/lib/logger"
	"gocode/cross_domain_auth/util"
	"testing"
)

type STYPE uint8

const (
	AUC_RQST     STYPE = 0x51
	AUC_RESP     STYPE = 0x52
	AUC_KEY_EXC  STYPE = 0x53
)

func (f STYPE) GetString() string {
	return [...]string{
		"AUC_RQST",
		"AUC_RESP",
		"AUC_KEY_EXEC",
	}[f-AUC_RQST]
}

func (f STYPE) CheckValid() bool {
	return f >= AUC_RQST && f <= AUC_KEY_EXC
}

type PID uint8

const (
	PID_RESERVED PID = 0x0
	PID_SIGN     PID = 0x1
	PID_MAC      PID = 0x2
	PID_BOTH     PID = 0x3
)

func (f PID) GetString() string {
	return [...]string{
		"PID_RESERVED",
		"PID_SIGN",
		"PID_MAC",
		"PID_BOTH",
	}[f-PID_RESERVED]
}

func (f PID) CheckValid() bool {
	return f <= PID_BOTH
}

type AucRqst struct {
	Stype STYPE  `ldacs:"name:S_TYPE; size:8; type:set"`
	Ver   uint8  `ldacs:"name:VER; size:3; type:set"`
	PID   PID    `ldacs:"name:PID; size:2; type:set"`
	SAC_AS uint16 `ldacs:"name:SAC_AS; size:12; type:set"`
	AUTHID  uint8   `ldacs:"name:PID; size:2; type:set"`
	ENCRID   uint8   `ldacs:"name:PID; size:2; type:set"`
	N1    []byte `ldacs:"name:N1; bytes_size: 16; type:fbytes"`
}

func TestTag(t *testing.T) {
	rqst := AucRqst{
		Stype: 0x51,
		Ver:   0x1,
		PID:   0x0,
		SAC_AS:   0xABC,
		AUTHID:  0x1,
		ENCRID:   0x0,
		//N1:    make([]byte, 16),
		N1:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
	}
	bytes, err := util.MarshalLdacsPkt(rqst)

	if err != nil {
		logger.Error("Validation failed:", err)
	} else {
		logger.Info("Validation succeeded")
	}

	logger.Warn("Marshaled:", bytes)

	rqst2 := AucRqst{
		//N1: make([]byte, 3),
	}
	_, err = util.UnmarshalLdacsPkt(bytes, &rqst2)
	if err != nil {
		logger.Error(err)
	}

	logger.Warn("Unmarshaled: ", rqst2)
}

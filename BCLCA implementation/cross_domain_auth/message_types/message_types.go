package message_types

type STYPE uint8

const (
	CR_AUC_RQST_NOTIC STYPE = 0x61
	CR_AUC_RQST_REPLY STYPE = 0x62
	CR_AUC_RQST_1     STYPE = 0x63
	CR_AUC_RQST_2     STYPE = 0x64
	CR_AUC_RESP       STYPE = 0x65
	CR_AUC_KEY_EXC    STYPE = 0x66
)

func (f STYPE) GetString() string {
	return [...]string{
		"CR_AUC_RQST_NOTIC",
		"CR_AUC_RQST_REPLY",
		"CR_AUC_RQST_1",
		"CR_AUC_RQST_2",
		"CR_AUC_RESP",
		"CR_AUC_KEY_EXC",
	}[f-CR_AUC_RQST_NOTIC]
}

func (f STYPE) CheckValid() bool {
	return f >= CR_AUC_RQST_NOTIC && f <= CR_AUC_KEY_EXC
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


type CrAucRqstNotic struct {
	Stype   uint8  `ldacs:"name:S_TYPE; size:8; type:set"`
	Ver     uint8  `ldacs:"name:VER; size:3; type:set"`
	PID     uint8   `ldacs:"name:PID; size:2; type:set"`
	UI_AC1 uint8  `ldacs:"name:UI_AC1; size:8; type:set"`
	AUTHID  uint8  `ldacs:"name:AUTHID; size:2; type:set"`
	ENCRID  uint8  `ldacs:"name:ENCRID; size:2; type:set"`
	PAD     uint8  `ldacs:"name:PAD; size:7; type:set"`
	Nonce   []byte `ldacs:"name:Nonce; bytes_size:16; type:fbytes"`
	M1      []byte `ldacs:"name:M1; bytes_size:39; type:fbytes"`
}

type CrAucRqstReply struct {
	Stype   uint8  `ldacs:"name:S_TYPE; size:8; type:set"`
	Ver     uint8  `ldacs:"name:VER; size:3; type:set"`
	PID     uint8  `ldacs:"name:PID; size:2; type:set"`
	UI_AC2 uint8  `ldacs:"name:UI_AC2; size:8; type:set"`
	AUTHID  uint8  `ldacs:"name:AUTHID; size:2; type:set"`
	ENCRID  uint8  `ldacs:"name:ENCRID; size:2; type:set"`
	PAD     uint8  `ldacs:"name:PAD; size:7; type:set"`
	Nonce   []byte `ldacs:"name:Nonce; bytes_size:16; type:fbytes"`
	M2      []byte `ldacs:"name:M2; bytes_size:3; type:fbytes"`
}

type CrAucRqst1 struct {
	Stype     uint8  `ldacs:"name:S_TYPE; size:8; type:set"`
	Ver       uint8  `ldacs:"name:VER; size:3; type:set"`
	PID       uint8  `ldacs:"name:PID; size:2; type:set"`
	SAC_AS1_2 uint16 `ldacs:"name:SAC_AS1_2; size:12; type:set"`
	AUTHID    uint8  `ldacs:"name:AUTHID; size:2; type:set"`
	ENCRID    uint8  `ldacs:"name:ENCRID; size:2; type:set"`
	PAD       uint8  `ldacs:"name:PAD; size:3; type:set"`
	Nonce     []byte `ldacs:"name:Nonce; bytes_size:16; type:fbytes"`
	M3        []byte `ldacs:"name:M3; bytes_size:69; type:fbytes"`
}

type CrAucRqst2 struct {
	Stype   uint8  `ldacs:"name:S_TYPE; size:8; type:set"`
	Ver     uint8  `ldacs:"name:VER; size:3; type:set"`
	PID     uint8  `ldacs:"name:PID; size:2; type:set"`
	UI_AC1 uint8  `ldacs:"name:UI_AC1; size:8; type:set"`
	AUTHID  uint8  `ldacs:"name:AUTHID; size:2; type:set"`
	ENCRID  uint8  `ldacs:"name:ENCRID; size:2; type:set"`
	PAD     uint8  `ldacs:"name:PAD; size:7; type:set"`
	Nonce   []byte `ldacs:"name:Nonce; bytes_size:16; type:fbytes"`
	M4      []byte `ldacs:"name:M4; bytes_size:72; type:fbytes"`
}

type CrAucResp struct {
	Stype   uint8  `ldacs:"name:S_TYPE; size:8; type:set"`
	Ver     uint8  `ldacs:"name:VER; size:3; type:set"`
	PID     uint8  `ldacs:"name:PID; size:2; type:set"`
	UI_AC2 uint8  `ldacs:"name:UI_AC2; size:8; type:set"`
	AUTHID  uint8  `ldacs:"name:AUTHID; size:2; type:set"`
	ENCRID  uint8  `ldacs:"name:ENCRID; size:2; type:set"`
	PAD     uint8  `ldacs:"name:PAD; size:7; type:set"`
	Nonce   []byte `ldacs:"name:Nonce; bytes_size:16; type:fbytes"`
	M5      []byte `ldacs:"name:M5; bytes_size:65; type:fbytes"`
}

type CrAucKeyExc struct {
	Stype     uint8  `ldacs:"name:S_TYPE; size:8; type:set"`
	Ver       uint8  `ldacs:"name:VER; size:3; type:set"`
	PID       uint8  `ldacs:"name:PID; size:2; type:set"`
	SAC_AS1_2 uint16 `ldacs:"name:SAC_AS1_2; size:12; type:set"`
	AUTHID    uint8  `ldacs:"name:AUTHID; size:2; type:set"`
	ENCRID    uint8  `ldacs:"name:ENCRID; size:2; type:set"`
	PAD       uint8  `ldacs:"name:PAD; size:3; type:set"`
	Nonce     []byte `ldacs:"name:Nonce; bytes_size:16; type:fbytes"`
	MAS1      []byte `ldacs:"name:MAS1; bytes_size:32; type:fbytes"`
}

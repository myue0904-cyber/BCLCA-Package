package as1

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"

	"gocode/cross_domain_auth/hash_utils"
	"gocode/cross_domain_auth/message_types"

	"gocode/cross_domain_auth/util"

	"github.com/cloudflare/circl/cipher/ascon"
	"github.com/hdt3213/godis/lib/logger"
)

type AS1 struct {
	curve  elliptic.Curve
	n      *big.Int 
	Gx, Gy *big.Int 

	UA_AS1  uint32
	SAC_AS1 uint16
	x_AS1   *big.Int
	y_AS1   *big.Int
	X_AS1   []byte 
	Y_AS1   []byte 

	UI_AC1 uint8
	X_AC1  []byte
	Y_AC1  []byte
	KS1    []byte

	port       string
	usedNonces map[string]bool
	mutex      sync.RWMutex

	SAC_AS1_2 uint16
	b         *big.Int
	B         []byte
	UI_AC2   uint8

	cryptoUtils *hash_utils.CryptoUtils
}

func NewAS1(port string) *AS1 {
	curve := elliptic.P256()
	params := curve.Params()

	as1 := &AS1{
		curve:       curve,
		n:           params.N,
		Gx:          params.Gx,
		Gy:          params.Gy,
		usedNonces:  make(map[string]bool),
		port:        port,
		cryptoUtils: &hash_utils.CryptoUtils{},
	}

	as1.initializeKeys()

	fmt.Println("\n=== AS1系统初始化完成 ===")
	fmt.Printf("UA_AS1: 0x%07x\n", as1.UA_AS1)
	fmt.Printf("SAC_AS1: 0x%03x\n", as1.SAC_AS1)
	fmt.Printf("X_AS1: %x\n", as1.X_AS1)
	fmt.Printf("Y_AS1: %x\n", as1.Y_AS1)
	fmt.Printf("UI_AC1: 0x%02x\n", as1.UI_AC1)
	fmt.Printf("X_AC1: %x\n", as1.X_AC1)
	fmt.Printf("Y_AC1: %x\n", as1.Y_AC1)
	fmt.Printf("KS1: %x\n", as1.KS1)
	fmt.Println("=======================")

	return as1
}

func (as1 *AS1) initializeKeys() {
	as1.UA_AS1 = 0xABC1DEF
	as1.SAC_AS1 = 0xABC

	as1.x_AS1 = new(big.Int)
	as1.x_AS1.SetString("7dee9e7dfe2253a21e813fcba567efdee75ed82d2dd9692b40b0f24cb083b054", 16)
	as1.y_AS1 = new(big.Int)
	as1.y_AS1.SetString("75babf6f36f1c6f665f6ff957274d8f3507ca63c209d57ed7fca35f862c7f670", 16)

	X_AS1_x, X_AS1_y := as1.curve.ScalarBaseMult(as1.x_AS1.Bytes())
	as1.X_AS1 = elliptic.MarshalCompressed(as1.curve, X_AS1_x, X_AS1_y)

	Y_AS1_x, Y_AS1_y := as1.curve.ScalarBaseMult(as1.y_AS1.Bytes())
	as1.Y_AS1 = elliptic.MarshalCompressed(as1.curve, Y_AS1_x, Y_AS1_y)

	as1.UI_AC1 = 0x5A

	X_AC1_x := new(big.Int)
	X_AC1_x.SetString("640eaf776951b46e236afc6f9afa40d6f6dac3eb947006e184b51bedc53377df", 16)
	X_AC1_y := new(big.Int)
	X_AC1_y.SetString("995f5eef331133efd99c16494307b2029002221d815f64d97528c773551424a0", 16)
	as1.X_AC1 = elliptic.MarshalCompressed(as1.curve, X_AC1_x, X_AC1_y)

	Y_AC1_x := new(big.Int)
	Y_AC1_x.SetString("7f10f788dbdce233e2cf17db2b54fd9c514a420e865f9067427e80d6657e0df", 16)
	Y_AC1_y := new(big.Int)
	Y_AC1_y.SetString("6571ed1aa4c4df65c6e9d56c8d1730f6fc0fa1d1558e00538386dd5b68f8fd7f", 16)
	as1.Y_AC1 = elliptic.MarshalCompressed(as1.curve, Y_AC1_x, Y_AC1_y)

	as1.KS1 = []byte{0x08, 0xb8, 0x9a, 0x33, 0x10, 0xd9, 0xdd, 0x7f, 0x50, 0x44, 0x04, 0x5d, 0x95, 0x5f, 0xb4, 0x5e}
}

func (as1 *AS1) Start() {
	listener, err := net.Listen("tcp", as1.port)
	if err != nil {
		log.Fatal("启动AS1服务器失败:", err)
	}
	defer listener.Close()

	fmt.Printf("[AS1] 监听端口 %s\n", as1.port[1:])

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go as1.handleConnection(conn)
	}
}

func (as1 *AS1) handleConnection(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Printf("[AS1] 读取数据失败 from %s: %v", addr, err)
		}
		return
	}

	data := buffer[:n]
	if len(data) == 0 {
		return
	}

	stype := data[0]
	switch stype {
	case byte(message_types.CR_AUC_RQST_REPLY):
		as1.handleCrAucRqstReply(conn, addr, data)
	case byte(message_types.CR_AUC_RESP):
		as1.handleCrAucResp(conn, addr, data)
	default:
		log.Printf("[AS1] 未知消息类型: %d from %s", stype, addr)
	}
}

func (as1 *AS1) handleCrAucRqstReply(_ net.Conn, addr string, data []byte) {
	resp := message_types.CrAucRqstReply{

	}
	_, err := util.UnmarshalLdacsPkt(data, &resp)
	if err != nil {
		log.Printf("[AC] 反序列化CR_AUC_RQST_REPLY失败: %v", err)
		return
	}

	fmt.Printf("[AS1] 收到来自 %s 的消息: CR_AUC_RQST_REPLY\n", addr)
	logger.Warn("Unmarshaled: ", resp)

	nonceStr := fmt.Sprintf("%x", resp.Nonce)
	as1.mutex.Lock()
	if as1.usedNonces[nonceStr] {
		as1.mutex.Unlock()
		log.Printf("[AS1] N2已使用: %s", nonceStr)
		return
	}
	as1.usedNonces[nonceStr] = true
	as1.mutex.Unlock()

	as1.UI_AC2 = resp.UI_AC2

	if len(resp.M2) < 3 {
		log.Printf("[AS1] M2长度不正确: %d", len(resp.M2))
		return
	}

	UI_AC1_extract := resp.M2[0]
	xor_result := resp.M2[1:3]

	SAC_AS1_2_bytes := xorBytes(uint12ToBytes(as1.SAC_AS1), xor_result)
	SAC_AS1_2 := bytesToUint12(SAC_AS1_2_bytes)
	as1.SAC_AS1_2 = SAC_AS1_2

	if !bytesEqual([]byte{UI_AC1_extract}, uint8ToBytes(as1.UI_AC1)) {
		log.Printf("[AS1] UI_AC1不匹配")
		return
	}
	
	N3 := make([]byte, 16)
	if _, err := rand.Read(N3); err != nil {
		log.Printf("[AS1] 生成N3失败: %v", err)
		return
	}

	N3Str := fmt.Sprintf("%x", N3)
	as1.mutex.Lock()
	as1.usedNonces[N3Str] = true
	as1.mutex.Unlock()

	as1.b, err = rand.Int(rand.Reader, as1.n)
	if err != nil {
		log.Printf("[AS1] 生成随机数b失败: %v", err)
		return
	}

	B_x, B_y := as1.curve.ScalarBaseMult(as1.b.Bytes())
	as1.B = elliptic.MarshalCompressed(as1.curve, B_x, B_y)

	Y_AC1_x, Y_AC1_y := elliptic.UnmarshalCompressed(as1.curve, as1.Y_AC1)
	yY_x, yY_y := as1.curve.ScalarMult(Y_AC1_x, Y_AC1_y, as1.y_AS1.Bytes())
	yY := elliptic.MarshalCompressed(as1.curve, yY_x, yY_y)
	AD := as1.cryptoUtils.H1(yY)

	PT := append(uint12ToBytes(as1.SAC_AS1_2), as1.B...)
	PT = append(PT, uint8ToBytes(as1.UI_AC1)...)
	PT = append(PT, uint8ToBytes(as1.UI_AC2)...)
	PT = append(PT, N3...)

	CT := as1.asconEncrypt(as1.KS1, N3, AD, PT)
	M3 := CT

	crAucRqst1 := &message_types.CrAucRqst1{
		Stype:     0x63,
		Ver:       0x1,
		PID:       0x0,
		SAC_AS1_2: as1.SAC_AS1_2,
		AUTHID:    0x1,
		ENCRID:    0x2,
		PAD:       0x0,
		Nonce:     N3,
		M3:        M3,
	}

	msg, err := util.MarshalLdacsPkt(crAucRqst1)

	if err != nil {
		logger.Error("Validation failed:", err)
	} else {
		logger.Info("Validation succeeded")
	}

	logger.Warn("Marshaled:", msg) 
	as1.sendToAC1(msg)
	fmt.Printf("[AS1] 已发送CR_AUC_RQST_1至AC1\n")
}

func (as1 *AS1) handleCrAucResp(_ net.Conn, addr string, data []byte) {
	resp := message_types.CrAucResp{}
	_, err := util.UnmarshalLdacsPkt(data, &resp)
	if err != nil {
		log.Printf("[AS] 反序列化CR_AUC_RESP失败: %v", err)
		return
	}

	fmt.Printf("[AS1] 收到来自 %s 的消息: CR_AUC_RESP\n", addr)

	logger.Warn("Unmarshaled: ", resp)

	nonceStr := fmt.Sprintf("%x", resp.Nonce)
	as1.mutex.Lock()
	if as1.usedNonces[nonceStr] {
		as1.mutex.Unlock()
		log.Printf("[AS1] N5已使用: %s", nonceStr)
		return
	}
	as1.usedNonces[nonceStr] = true
	as1.mutex.Unlock()

	if len(resp.M5) < 65 { 
		log.Printf("[AS1] M5长度不正确: %d", len(resp.M5))
		return
	}

	J_extract := resp.M5[0:33]
	mac_AC2_extract := resp.M5[33:65]

	J_x, J_y := elliptic.UnmarshalCompressed(as1.curve, J_extract)
	if J_x == nil {
		log.Printf("[AS1] 解压缩J点失败")
		return
	}
	k := as1.cryptoUtils.H2(uint12ToBytes(as1.SAC_AS1_2), []byte{as1.UI_AC2}, as1.B, J_extract, resp.Nonce)
	kb := new(big.Int).Mul(k, as1.b)
	kb.Mod(kb, as1.n)

	sum := new(big.Int).Add(kb, as1.x_AS1)
	sum.Add(sum, as1.y_AS1)
	sum.Mod(sum, as1.n)

	temp_point_x, temp_point_y := as1.curve.ScalarMult(J_x, J_y, sum.Bytes())
	temp_compressed := elliptic.MarshalCompressed(as1.curve, temp_point_x, temp_point_y)
	h4_input := append(append(uint12ToBytes(as1.SAC_AS1_2), as1.UI_AC2), temp_compressed...)
	KS_AS1_AC2 := as1.cryptoUtils.H4(h4_input)

	k_bytes := k.Bytes()
	if len(k_bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(k_bytes):], k_bytes)
		k_bytes = padded
	}

	mac_AC2 := hmac.New(sha256.New, KS_AS1_AC2)
	mac_AC2.Write(k_bytes)
	expected_mac := mac_AC2.Sum(nil)

	if !hmac.Equal(mac_AC2_extract, expected_mac) {
		log.Printf("[AS1] MAC验证失败")
		return
	}

	fmt.Printf("AC2被AS1认证成功! AS1会话密钥: %x\n", KS_AS1_AC2)
	N6 := make([]byte, 16)
	if _, err := rand.Read(N6); err != nil {
		log.Printf("[AS1] 生成N6失败: %v", err)
		return
	}

	N6Str := fmt.Sprintf("%x", N6)
	as1.mutex.Lock()
	as1.usedNonces[N6Str] = true
	as1.mutex.Unlock()
	concatenated_data := append(uint12ToBytes(as1.SAC_AS1_2), []byte{as1.UI_AC2}...)
	mac_AS1_hmac := hmac.New(sha256.New, KS_AS1_AC2)
	mac_AS1_hmac.Write(concatenated_data)
	mac_AS1 := mac_AS1_hmac.Sum(nil)

	crAucKeyExc := &message_types.CrAucKeyExc{
		Stype:     0x66,
		Ver:       0x1,
		PID:       0x0,
		SAC_AS1_2: as1.SAC_AS1_2,
		AUTHID:    0x2,
		ENCRID:    0x1,
		PAD:       0x0,
		Nonce:     N6,
		MAS1:      mac_AS1,
	}

	msg, err := util.MarshalLdacsPkt(crAucKeyExc)

	if err != nil {
		logger.Error("Validation failed:", err)
	} else {
		logger.Info("Validation succeeded")
	}

	logger.Warn("Marshaled:", msg) 
	as1.sendToAC2(msg)
	fmt.Printf("[AS1] 已发送CR_AUC_KEY_EXC至AC2\n")
}

func (as1 *AS1) asconEncrypt(key, nonce, ad, plaintext []byte) []byte {
	cipher, err := ascon.New(key, ascon.Ascon128)
	if err != nil {
		log.Printf("创建ASCON失败: %v", err)
		return nil
	}
	return cipher.Seal(nil, nonce, plaintext, ad)
}

func (as1 *AS1) sendToAC1(data []byte) {
	conn, err := net.Dial("tcp", "localhost:8000")
	if err != nil {
		log.Printf("[AS1] 连接到AC1失败: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		log.Printf("[AS1] 发送数据失败: %v", err)
		return
	}
}

func (as1 *AS1) sendToAC2(data []byte) {
	conn, err := net.Dial("tcp", "localhost:8001")
	if err != nil {
		log.Printf("[AS1] 连接到AC2失败: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		log.Printf("[AS1] 发送数据失败: %v", err)
		return
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func uint12ToBytes(value uint16) []byte {
	value = value & 0x0FFF
	return []byte{
		byte((value >> 8) & 0xFF), 
		byte(value & 0xFF),       
	}
}

func bytesToUint12(data []byte) uint16 {
	if len(data) < 2 {
		return 0
	}
	value := uint16(data[0])<<8 | uint16(data[1])
	return value & 0x0FFF
}

func uint8ToBytes(value uint8) []byte {
	return []byte{value}
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("异或操作的字节切片长度必须相同")
	}
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

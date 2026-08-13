package ac2

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

type AC2 struct {
	curve  elliptic.Curve
	n      *big.Int
	Gx, Gy *big.Int

	UI_AC2 uint8
	x_AC2  *big.Int
	y_AC2  *big.Int
	X_AC2  []byte
	Y_AC2  []byte

	UI_AC1 uint8
	X_AC1  []byte
	Y_AC1  []byte

	X_AS1 []byte
	Y_AS1 []byte

	SK_AC12 []byte

	port        string
	usedNonces  map[string]bool
	KS_AC2_AS1 []byte

	UA_AS1    uint32
	SAC_AS1_2 uint16

	cryptoUtils *hash_utils.CryptoUtils
	mutex       sync.RWMutex
}

func bitsToUint32(bits []bool) uint32 {
	var result uint32
	for i := 0; i < len(bits) && i < 32; i++ {
		if bits[i] {
			result |= 1 << (uint(len(bits)-1-i))
		}
	}
	return result
}

func NewAC2(port string) *AC2 {
	curve := elliptic.P256()
	params := curve.Params()

	ac2 := &AC2{
		curve:       curve,
		n:           params.N,
		Gx:          params.Gx,
		Gy:          params.Gy,
		port:        port,
		usedNonces:  make(map[string]bool),
		cryptoUtils: &hash_utils.CryptoUtils{},
	}

	ac2.initializeKeys()

	fmt.Println("\n=== AC2系统初始化完成 ===")
	fmt.Printf("UI_AC2: 0x%02x\n", ac2.UI_AC2)
	fmt.Printf("X_AC2: %x\n", ac2.X_AC2)
	fmt.Printf("Y_AC2: %x\n", ac2.Y_AC2)
	fmt.Printf("UI_AC1: 0x%02x\n", ac2.UI_AC1)
	fmt.Printf("X_AC1: %x\n", ac2.X_AC1)
	fmt.Printf("Y_AC1: %x\n", ac2.Y_AC1)
	fmt.Printf("X_AS1: %x\n", ac2.X_AS1)
	fmt.Printf("Y_AS1: %x\n", ac2.Y_AS1)
	fmt.Printf("SK_AC12: %x\n", ac2.SK_AC12)
	fmt.Println("=======================")

	return ac2
}

func (ac2 *AC2) initializeKeys() {

	ac2.UI_AC2 = 0x5B

	ac2.x_AC2 = new(big.Int)
	ac2.x_AC2.SetString("4cc5754a7e940477b7d9dcdbb0d151d8a1fc6d71e965511ff1e8c90b1f5befd9", 16)
	ac2.y_AC2 = new(big.Int)
	ac2.y_AC2.SetString("f905aff6f7015a5ed1e879dfdbd34e0bb9493583b1de3f836e155c013c50a6e9", 16)

	X_AC2_x, X_AC2_y := ac2.curve.ScalarBaseMult(ac2.x_AC2.Bytes())
	ac2.X_AC2 = elliptic.MarshalCompressed(ac2.curve, X_AC2_x, X_AC2_y)

	Y_AC2_x, Y_AC2_y := ac2.curve.ScalarBaseMult(ac2.y_AC2.Bytes())
	ac2.Y_AC2 = elliptic.MarshalCompressed(ac2.curve, Y_AC2_x, Y_AC2_y)

	ac2.UI_AC1 = 0x5A

	X_AC1_x := new(big.Int)
	X_AC1_x.SetString("640eaf776951b46e236afc6f9afa40d6f6dac3eb947006e184b51bedc53377df", 16)
	X_AC1_y := new(big.Int)
	X_AC1_y.SetString("995f5eef331133efd99c16494307b2029002221d815f64d97528c773551424a0", 16)
	ac2.X_AC1 = elliptic.MarshalCompressed(ac2.curve, X_AC1_x, X_AC1_y)

	Y_AC1_x := new(big.Int)
	Y_AC1_x.SetString("7f10f788dbdce233e2cf17db2b54fd9c514a420e865f9067427e80d6657e0df", 16)
	Y_AC1_y := new(big.Int)
	Y_AC1_y.SetString("6571ed1aa4c4df65c6e9d56c8d1730f6fc0fa1d1558e00538386dd5b68f8fd7f", 16)
	ac2.Y_AC1 = elliptic.MarshalCompressed(ac2.curve, Y_AC1_x, Y_AC1_y)

	X_AS1_x := new(big.Int)
	X_AS1_x.SetString("ad86c07447aa3649d673ae3833181dad3aa9de2f13c6d107cc456b962ddec9f", 16)
	X_AS1_y := new(big.Int)
	X_AS1_y.SetString("cdf3a5c8c36d243ecb9eefff7410cf376dcdfc8f0c86e617028830b740d22563", 16)
	ac2.X_AS1 = elliptic.MarshalCompressed(ac2.curve, X_AS1_x, X_AS1_y)

	Y_AS1_x := new(big.Int)
	Y_AS1_x.SetString("9ff32ac569fd8a6f327f3fda4f0ea98a3cf4ce1ae23c6ad299efa0be27f7d2c1", 16)
	Y_AS1_y := new(big.Int)
	Y_AS1_y.SetString("9a2e1f979b2f4dc6110f259f30fed6f9bfc028862ab0d5bd09be77c1ba9c6731", 16)
	ac2.Y_AS1 = elliptic.MarshalCompressed(ac2.curve, Y_AS1_x, Y_AS1_y)

	ac2.SK_AC12 = []byte{0xb6, 0x61, 0x0f, 0x27, 0xb6, 0xe6, 0xb2, 0x32, 0x5a, 0x38, 0x27, 0xac, 0x83, 0xa5, 0x37, 0x0a}
}

func (ac2 *AC2) Start() {
	listener, err := net.Listen("tcp", ac2.port)
	if err != nil {
		log.Fatal("启动AC2服务器失败:", err)
	}
	defer listener.Close()

	fmt.Printf("[AC2] 监听端口 %s\n", ac2.port[1:])

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go ac2.handleConnection(conn)
	}
}

func (ac2 *AC2) handleConnection(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Printf("[AC2] 读取数据失败 from %s: %v", addr, err)
		}
		return
	}

	data := buffer[:n]
	if len(data) == 0 {
		return
	}

	stype := data[0]
	switch stype {
	case byte(message_types.CR_AUC_RQST_NOTIC):
		ac2.handleCrAucRqstNotic(conn, addr, data)
	case byte(message_types.CR_AUC_RQST_2):
		ac2.handleCrAucRqst2(conn, addr, data)
	case byte(message_types.CR_AUC_KEY_EXC):
		ac2.handleCrAucKeyExc(conn, addr, data)
	default:
		log.Printf("[AC2] 未知消息类型: %d from %s", stype, addr)
	}
}

func (ac2 *AC2) handleCrAucRqstNotic(_ net.Conn, addr string, data []byte) {
	resp := message_types.CrAucRqstNotic{

	}
	_, err := util.UnmarshalLdacsPkt(data, &resp)
	if err != nil {
		log.Printf("[AC2] 反序列化CR_AUC_RQST_NOTIC失败: %v", err)
		return
	}

	fmt.Printf("[AC2] 收到来自 %s 的消息: CR_AUC_RQST_NOTIC\n", addr)

	logger.Warn("Unmarshaled: ", resp)

	nonceStr := fmt.Sprintf("%x", resp.Nonce)
	ac2.mutex.Lock()
	if ac2.usedNonces[nonceStr] {
		ac2.mutex.Unlock()
		log.Printf("[AC2] N1已使用: %s", nonceStr)
		return
	}
	ac2.usedNonces[nonceStr] = true
	ac2.mutex.Unlock()

	Y_AC1_x, Y_AC1_y := elliptic.UnmarshalCompressed(ac2.curve, ac2.Y_AC1)
	if Y_AC1_x == nil {
		log.Printf("[AC2] 无法解析Y_AC1点")
		return
	}

	yY_x, yY_y := ac2.curve.ScalarMult(Y_AC1_x, Y_AC1_y, ac2.y_AC2.Bytes())
	yY_bytes := elliptic.MarshalCompressed(ac2.curve, yY_x, yY_y)

	A := ac2.cryptoUtils.H1(yY_bytes)

	cipher, err := ascon.New(ac2.SK_AC12, ascon.Ascon128)
	if err != nil {
		log.Printf("[AC2] ASCON解密初始化失败: %v", err)
		return
	}

	CT := resp.M1
	PT, err := cipher.Open(nil, resp.Nonce, CT, A)
	if err != nil {
		log.Printf("[AC2] ASCON解密失败: %v", err)
		return
	}

	parsedUI_AC1, parsedUA_AS1, parsedSAC_AS1, parsedUI_AC2, parsedN1 := ac2.parsePlaintext(PT)

	ac2.UA_AS1 = parsedUA_AS1

    if !bitsEqual([]bool{parsedUI_AC1 == ac2.UI_AC1}, []bool{true}) {
		log.Printf("[AC2] UI_AC1 不匹配")
		return
	}

	if !bitsEqual([]bool{parsedUI_AC2 == ac2.UI_AC2}, []bool{true}) {
		log.Printf("[AC2] UI_AC2 不匹配")
		return
	}

	if !bytesEqual(parsedN1, resp.Nonce) {
		log.Printf("[AC2] N1 不匹配")
		return
	}

	N2 := make([]byte, 16)
	if _, err := rand.Read(N2); err != nil {
		log.Printf("[AC2] 生成N2失败: %v", err)
		return
	}

	N2Str := fmt.Sprintf("%x", N2)
	ac2.mutex.Lock()
	ac2.usedNonces[N2Str] = true
	ac2.mutex.Unlock()

	SAC_AS1_2 := 0xDEF
	ac2.SAC_AS1_2 = uint16(SAC_AS1_2)

	xorResult := xorBytes(uint12ToBytes(parsedSAC_AS1), uint12ToBytes(ac2.SAC_AS1_2))
	M2 := append(uint8ToBytes(ac2.UI_AC1),xorResult...)

	crAucRqstReply := &message_types.CrAucRqstReply{
		Stype:  0x62,
		Ver:    0x1,
		PID:    0x0,
		UI_AC2: ac2.UI_AC2,
		AUTHID: 0x1,
		ENCRID: 0x1,
		PAD:    0x0,
		Nonce:  N2,
		M2:     M2,
	}

	msg, err := util.MarshalLdacsPkt(crAucRqstReply)

	if err != nil {
		logger.Error("Validation failed:", err)
	} else {
		logger.Info("Validation succeeded")
	}

	logger.Warn("Marshaled:", msg)

	ac2.sendToAS1(msg)
	fmt.Printf("[AC2] 已发送CR_AUC_RQST_REPLY至AS1\n")
}

func (ac2 *AC2) handleCrAucRqst2(_ net.Conn, addr string, data []byte) {
	resp := message_types.CrAucRqst2{

	}
	_, err := util.UnmarshalLdacsPkt(data, &resp)
	if err != nil {
		log.Printf("[AC2] 反序列化CR_AUC_RQST_2失败: %v", err)
		return
	}

	fmt.Printf("[AC2] 收到来自 %s 的消息: CR_AUC_RQST_2\n", addr)

	logger.Warn("Unmarshaled: ", resp)

	nonceStr := fmt.Sprintf("%x", resp.Nonce)
	ac2.mutex.Lock()
	if ac2.usedNonces[nonceStr] {
		ac2.mutex.Unlock()
		log.Printf("[AC2] N4已使用: %s", nonceStr)
		return
	}
	ac2.usedNonces[nonceStr] = true
	ac2.mutex.Unlock()

	if len(resp.M4) < 72 {
		log.Printf("[AC2] M4长度不正确: %d", len(resp.M4))
		return
	}

	D_extract := resp.M4[0:33]
	f_extract := resp.M4[33:72]

	D_x, D_y := elliptic.UnmarshalCompressed(ac2.curve, D_extract)
	if D_x == nil {
		log.Printf("[AC2] 无法解析D点")
		return
	}

	privateSum := new(big.Int).Add(ac2.x_AC2, ac2.y_AC2)
	privateSum.Mod(privateSum, ac2.n)

	e_prime_x, e_prime_y := ac2.curve.ScalarMult(D_x, D_y, privateSum.Bytes())

	h3_e_prime := ac2.cryptoUtils.H3(e_prime_x, e_prime_y)

	if len(h3_e_prime) != len(f_extract) {
		log.Printf("[AC2] h3_e_prime长度与f_extract不匹配: %d vs %d", len(h3_e_prime), len(f_extract))
		return
	}

	concatenated_data_recovered := xorBytes(h3_e_prime,f_extract)
	parsedUI_AC1, parsedUA_AS1, parsedSAC_AS1_2, parsedB := parseData(concatenated_data_recovered)

	if parsedUI_AC1 != ac2.UI_AC1 {
		log.Printf("[AC2] UI_AC1 不匹配")
	}

	if parsedUA_AS1 != ac2.UA_AS1 {
		log.Printf("[AC2] UA_AS1 不匹配")
	}

	if parsedSAC_AS1_2 != ac2.SAC_AS1_2 {
		log.Printf("[AC2] SAC_AS1_2 不匹配")
	}

	B_x, B_y := elliptic.UnmarshalCompressed(ac2.curve, parsedB)
	if B_x == nil {
		log.Printf("[AC2] 无法解析B点")
		return
	}

	N5 := make([]byte, 16)
	if _, err := rand.Read(N5); err != nil {
		log.Printf("[AC2] 生成N5失败: %v", err)
		return
	}

	N5Str := fmt.Sprintf("%x", N5)
	ac2.mutex.Lock()
	ac2.usedNonces[N5Str] = true
	ac2.mutex.Unlock()

	j, err := rand.Int(rand.Reader, ac2.n)
	if err != nil {
		log.Printf("[AC2] 生成随机数j失败: %v", err)
		return
	}

	J_x, J_y := ac2.curve.ScalarBaseMult(j.Bytes())
	J_bytes := elliptic.MarshalCompressed(ac2.curve, J_x, J_y)

	k := ac2.cryptoUtils.H2(uint12ToBytes(ac2.SAC_AS1_2), []byte{ac2.UI_AC2}, parsedB, J_bytes, N5)
	k_bytes := k.Bytes()
	if len(k_bytes) < 32 {

		padded := make([]byte, 32)
		copy(padded[32-len(k_bytes):], k_bytes)
		k_bytes = padded
	}

	kB_x, kB_y := ac2.curve.ScalarMult(B_x, B_y, k.Bytes())

	X_AS1_x, X_AS1_y := elliptic.UnmarshalCompressed(ac2.curve, ac2.X_AS1)
	Y_AS1_x, Y_AS1_y := elliptic.UnmarshalCompressed(ac2.curve, ac2.Y_AS1)

	temp1_x, temp1_y := ac2.curve.Add(kB_x, kB_y, X_AS1_x, X_AS1_y)

	temp2_x, temp2_y := ac2.curve.Add(temp1_x, temp1_y, Y_AS1_x, Y_AS1_y)

	temp_point_x, temp_point_y := ac2.curve.ScalarMult(temp2_x, temp2_y, j.Bytes())
	temp_point_bytes := elliptic.MarshalCompressed(ac2.curve, temp_point_x, temp_point_y)

	keyData := append(append(uint12ToBytes(ac2.SAC_AS1_2), ac2.UI_AC2), temp_point_bytes...)
	ac2.KS_AC2_AS1 = ac2.cryptoUtils.H4(keyData)

	mac_AC2 := hmac.New(sha256.New, ac2.KS_AC2_AS1)
	mac_AC2.Write(k_bytes)
	mac_AC2_digest := mac_AC2.Sum(nil)

	M5 := make([]byte, len(J_bytes)+len(mac_AC2_digest))
	copy(M5, J_bytes)
	copy(M5[len(J_bytes):], mac_AC2_digest)

	crAucResp := &message_types.CrAucResp{
		Stype:  0x65,
		Ver:    0x1,
		PID:    0x0,
		UI_AC2: ac2.UI_AC2,
		AUTHID: 0x3,
		ENCRID: 0x1,
		PAD:    0x0,
		Nonce:  N5,
		M5:     M5,
	}

	msg, err := util.MarshalLdacsPkt(crAucResp)

	if err != nil {
		logger.Error("Validation failed:", err)
	} else {
		logger.Info("Validation succeeded")
	}

	logger.Warn("Marshaled:", msg)

	ac2.sendToAS1(msg)
	fmt.Printf("[AC2] 已发送CR_AUC_RESP至AS1\n")
}

func (ac2 *AC2) handleCrAucKeyExc(_ net.Conn, addr string, data []byte) {
	resp := message_types.CrAucKeyExc{

	}
	_, err := util.UnmarshalLdacsPkt(data, &resp)
	if err != nil {
		log.Printf("[AC] 反序列化CR_AUC_KEY_EXC失败: %v", err)
		return
	}

	fmt.Printf("[AC2] 收到来自 %s 的消息: CR_AUC_KEY_EXC\n", addr)

	logger.Warn("Unmarshaled: ", resp)

	nonceStr := fmt.Sprintf("%x", resp.Nonce)
	ac2.mutex.Lock()
	if ac2.usedNonces[nonceStr] {
		ac2.mutex.Unlock()
		log.Printf("[AC2] N6已使用: %s", nonceStr)
		return
	}
	ac2.usedNonces[nonceStr] = true
	ac2.mutex.Unlock()

	concatenated_data := append(uint12ToBytes(ac2.SAC_AS1_2), []byte{ac2.UI_AC2}...)

	mac_AS1 := hmac.New(sha256.New, ac2.KS_AC2_AS1)
	mac_AS1.Write(concatenated_data)
	mac_AS1_digest := mac_AS1.Sum(nil)

	if !hmac.Equal(resp.MAS1, mac_AS1_digest) {
		log.Printf("[AC2] 最终MAC验证失败")
		return
	}

	fmt.Printf("AS1被AC2认证成功! AC2会话密钥: %x\n", ac2.KS_AC2_AS1)
}

func (ac2 *AC2) sendToAS1(data []byte) {
	conn, err := net.Dial("tcp", "localhost:8002")
	if err != nil {
		log.Printf("[AC2] 连接到AS1失败: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		log.Printf("[AC2] 发送数据失败: %v", err)
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

func byteToBits(data []byte) []bool {
    bits := []bool{}
    for _, b := range data {
        for i := 7; i >= 0; i-- {
            bits = append(bits, (b>>i)&1 == 1)
        }
    }
    return bits
}

func extractBitField(bits []bool, start, length int) []bool {
    return bits[start : start+length]
}

func bitsEqual(a, b []bool) bool {
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

func (ac2 *AC2) parsePlaintext(P []byte) (uint8, uint32, uint16, uint8, []byte) {
	if len(P) != 23 {
		log.Printf("[AC2] 明文P长度错误: %d, 期望23", len(P))
		return 0, 0, 0, 0, nil
	}

	offset := 0

	UI_AC1 := P[offset]
	offset++

	combined := uint64(P[offset])<<32 |
	           uint64(P[offset+1])<<24 |
	           uint64(P[offset+2])<<16 |
	           uint64(P[offset+3])<<8 |
	           uint64(P[offset+4])

	UA_AS1 := uint32((combined >> 12) & 0x0FFFFFFF)
	SAC_AS1 := uint16(combined & 0x0FFF)
	offset += 5

	UI_AC2 := P[offset]
	offset++

	N1 := make([]byte, 16)
	copy(N1, P[offset:offset+16])

	return UI_AC1, UA_AS1, SAC_AS1, UI_AC2, N1
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

func parseData(data []byte) (uint8, uint32, uint16, []byte) {
	if len(data) != 39 {
		log.Printf("错误：数据长度错误: %d, 期望39字节", len(data))
		return 0, 0, 0, nil
	}

	offset := 0

	UI_AC1 := data[offset]
	offset++

	combined := uint64(data[offset])<<32 |
	           uint64(data[offset+1])<<24 |
	           uint64(data[offset+2])<<16 |
	           uint64(data[offset+3])<<8 |
	           uint64(data[offset+4])

	UA_AS1 := uint32((combined >> 12) & 0x0FFFFFFF)
	SAC_AS1_2 := uint16(combined & 0x0FFF)
	offset += 5

	B := make([]byte, 33)
	copy(B, data[offset:offset+33])

	return UI_AC1, UA_AS1, SAC_AS1_2, B
}
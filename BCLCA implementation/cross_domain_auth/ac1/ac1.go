package ac1

import (
	"crypto/elliptic"
	"crypto/rand"

	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"

	"gocode/cross_domain_auth/hash_utils"
	"gocode/cross_domain_auth/message_types"

	"github.com/cloudflare/circl/cipher/ascon"

	"gocode/cross_domain_auth/util"

	"github.com/hdt3213/godis/lib/logger"
)

type AC1 struct {
	curve  elliptic.Curve
	n      *big.Int
	Gx, Gy *big.Int

	UI_AC1 uint8
	x_AC1  *big.Int
	y_AC1  *big.Int
	X_AC1  []byte
	Y_AC1  []byte

	UA_AS1  uint32
	SAC_AS1 uint16
	X_AS1   []byte
	Y_AS1   []byte
	KS1     []byte

	UI_AC2  uint8
	X_AC2   []byte
	Y_AC2   []byte
	SK_AC12 []byte

	port       string
	usedNonces map[string]bool

	cryptoUtils *hash_utils.CryptoUtils
	mutex       sync.RWMutex
}

func NewAC1(port string) *AC1 {
	curve := elliptic.P256()
	params := curve.Params()

	ac1 := &AC1{
		curve:       curve,
		n:           params.N,
		Gx:          params.Gx,
		Gy:          params.Gy,
		port:        port,
		usedNonces:  make(map[string]bool),
		cryptoUtils: &hash_utils.CryptoUtils{},
	}

	ac1.initializeKeys()

	fmt.Println("\n=== AC1系统初始化完成 ===")
	fmt.Printf("UI_AC1: 0x%02x\n", ac1.UI_AC1)
	fmt.Printf("X_AC1: %x\n", ac1.X_AC1)
	fmt.Printf("Y_AC1: %x\n", ac1.Y_AC1)
	fmt.Printf("UA_AS1: 0x%07x\n", ac1.UA_AS1)
	fmt.Printf("SAC_AS1: 0x%03x\n", ac1.SAC_AS1)
	fmt.Printf("X_AS1: %x\n", ac1.X_AS1)
	fmt.Printf("Y_AS1: %x\n", ac1.Y_AS1)
	fmt.Printf("UI_AC2: 0x%02x\n", ac1.UI_AC2)
	fmt.Printf("X_AC2: %x\n", ac1.X_AC2)
	fmt.Printf("Y_AC2: %x\n", ac1.Y_AC2)
	fmt.Println("=======================")

	return ac1
}

func (ac1 *AC1) initializeKeys() {

	ac1.UI_AC1 = 0x5A

	ac1.x_AC1 = new(big.Int)
	ac1.x_AC1.SetString("25f9ae480342905eb4b078c6b87616b9f53057613098dc5bfdf84d0afc152db2", 16)
	ac1.y_AC1 = new(big.Int)
	ac1.y_AC1.SetString("f0dc44612ce39edfd9f16e49671e3a30149b3805143ee00d79ebed85765907d9", 16)

	X_AC1_x, X_AC1_y := ac1.curve.ScalarBaseMult(ac1.x_AC1.Bytes())
	ac1.X_AC1 = elliptic.MarshalCompressed(ac1.curve, X_AC1_x, X_AC1_y)

	Y_AC1_x, Y_AC1_y := ac1.curve.ScalarBaseMult(ac1.y_AC1.Bytes())
	ac1.Y_AC1 = elliptic.MarshalCompressed(ac1.curve, Y_AC1_x, Y_AC1_y)

	ac1.UA_AS1 = 0xABC1DEF
	ac1.SAC_AS1 = 0xABC

	X_AS1_x := new(big.Int)
	X_AS1_x.SetString("ad86c07447aa3649d673ae3833181dad3aa9de2f13c6d107cc456b962ddec9f", 16)
	X_AS1_y := new(big.Int)
	X_AS1_y.SetString("cdf3a5c8c36d243ecb9eefff7410cf376dcdfc8f0c86e617028830b740d22563", 16)
	ac1.X_AS1 = elliptic.MarshalCompressed(ac1.curve, X_AS1_x, X_AS1_y)

	Y_AS1_x := new(big.Int)
	Y_AS1_x.SetString("9ff32ac569fd8a6f327f3fda4f0ea98a3cf4ce1ae23c6ad299efa0be27f7d2c1", 16)
	Y_AS1_y := new(big.Int)
	Y_AS1_y.SetString("9a2e1f979b2f4dc6110f259f30fed6f9bfc028862ab0d5bd09be77c1ba9c6731", 16)
	ac1.Y_AS1 = elliptic.MarshalCompressed(ac1.curve, Y_AS1_x, Y_AS1_y)

	ac1.KS1 = []byte{0x08, 0xb8, 0x9a, 0x33, 0x10, 0xd9, 0xdd, 0x7f, 0x50, 0x44, 0x04, 0x5d, 0x95, 0x5f, 0xb4, 0x5e}

	ac1.UI_AC2 = 0x5B

	X_AC2_x := new(big.Int)
	X_AC2_x.SetString("6674dcd3925f2ea25953da1865156b94f7a49da76396cdb87a192ddb734618fc", 16)
	X_AC2_y := new(big.Int)
	X_AC2_y.SetString("127689edd3e5a226cec803b92db5de825709630b85fe0a09839c4a11d9255bc4", 16)
	ac1.X_AC2 = elliptic.MarshalCompressed(ac1.curve, X_AC2_x, X_AC2_y)

	Y_AC2_x := new(big.Int)
	Y_AC2_x.SetString("c73f33704b06eddc667f97ff061c252e66b30a7f66f94464d69fb86a797ca6ff", 16)
	Y_AC2_y := new(big.Int)
	Y_AC2_y.SetString("255c292a20edc178789db892149e7fb414adfff351dbed3834bfa53c5147e459", 16)
	ac1.Y_AC2 = elliptic.MarshalCompressed(ac1.curve, Y_AC2_x, Y_AC2_y)

	ac1.SK_AC12 = []byte{0xb6, 0x61, 0x0f, 0x27, 0xb6, 0xe6, 0xb2, 0x32, 0x5a, 0x38, 0x27, 0xac, 0x83, 0xa5, 0x37, 0x0a}
}

func (ac1 *AC1) Start() {

	go ac1.startServer()

	ac1.SendCR_AUC_RQST_NOTIC()
}

func (ac1 *AC1) startServer() {
	listener, err := net.Listen("tcp", ac1.port)
	if err != nil {
		log.Fatal("启动AC1服务器失败:", err)
	}
	defer listener.Close()

	fmt.Printf("[AC1] 监听端口 %s\n", ac1.port[1:])

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go ac1.handleConnection(conn)
	}
}

func (ac1 *AC1) handleConnection(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Printf("[AC1] 读取数据失败 from %s: %v", addr, err)
		}
		return
	}

	data := buffer[:n]
	if len(data) == 0 {
		return
	}

	stype := data[0]
	switch stype {
	case byte(message_types.CR_AUC_RQST_1):
		ac1.handleCrAucRqst1(conn, addr, data)
	default:
		log.Printf("[AC1] 未知消息类型: %d from %s", stype, addr)
	}
}

func (ac1 *AC1) SendCR_AUC_RQST_NOTIC() {

	N1 := make([]byte, 16)
	if _, err := rand.Read(N1); err != nil {
		log.Printf("[AC1] 生成N1失败: %v", err)
		return
	}

	N1Str := fmt.Sprintf("%x", N1)
	ac1.mutex.Lock()
	ac1.usedNonces[N1Str] = true
	ac1.mutex.Unlock()

	Y_AC2_x, Y_AC2_y := elliptic.UnmarshalCompressed(ac1.curve, ac1.Y_AC2)
	if Y_AC2_x == nil {
		log.Printf("[AC1] 解压缩Y_AC2公钥失败")
		return
	}

	yY_x, yY_y := ac1.curve.ScalarMult(Y_AC2_x, Y_AC2_y, ac1.y_AC1.Bytes())
	yY := elliptic.MarshalCompressed(ac1.curve, yY_x, yY_y)

	A := ac1.cryptoUtils.H1(yY)

	P := ac1.constructPlaintext(N1)

	CT := ac1.asconEncrypt(ac1.SK_AC12, N1, A, P)
	if CT == nil {
		log.Printf("[AC1] ASCON加密失败")
		return
	}
	M1 := CT

	crAucRqstNotic := &message_types.CrAucRqstNotic{
		Stype:   0x61,
		Ver:     0x1,
		PID:     0x0,
		UI_AC1: ac1.UI_AC1,
		AUTHID:  0x1,
		ENCRID:  0x2,
		PAD:     0x0,
		Nonce:   N1,
		M1:      M1,
	}

	msg, err := util.MarshalLdacsPkt(crAucRqstNotic)

	if err != nil {
		logger.Error("Validation failed:", err)
	} else {
		logger.Info("Validation succeeded")
	}

	logger.Warn("Marshaled:", msg)

	ac1.sendToAC2(msg)
	fmt.Printf("[AC1] 已发送CR_AUC_RQST_NOTIC至AC2\n")
}

func (ac1 *AC1) handleCrAucRqst1(_ net.Conn, addr string, data []byte) {
	resp := message_types.CrAucRqst1{}
	_, err := util.UnmarshalLdacsPkt(data, &resp)
	if err != nil {
		log.Printf("[AC] 反序列化CR_AUC_RQST_1失败: %v", err)
		return
	}

	fmt.Printf("[AC1] 收到来自 %s 的消息: CR_AUC_RQST_1\n", addr)

	logger.Warn("Unmarshaled: ", resp)

	nonceStr := fmt.Sprintf("%x", resp.Nonce)
	ac1.mutex.Lock()
	if ac1.usedNonces[nonceStr] {
		ac1.mutex.Unlock()
		log.Printf("[AC1] N3已使用: %s", nonceStr)
		return
	}
	ac1.usedNonces[nonceStr] = true
	ac1.mutex.Unlock()

	Y_AS1_x, Y_AS1_y := elliptic.UnmarshalCompressed(ac1.curve, ac1.Y_AS1)
	if Y_AS1_x == nil {
		log.Printf("[AC1] 解压缩Y_AS1公钥失败")
		return
	}

	yY_x, yY_y := ac1.curve.ScalarMult(Y_AS1_x, Y_AS1_y, ac1.y_AC1.Bytes())
	yY := elliptic.MarshalCompressed(ac1.curve, yY_x, yY_y)

	AD := ac1.cryptoUtils.H1(yY)

	PT := ac1.asconDecrypt(ac1.KS1, resp.Nonce, AD, resp.M3)
	if PT == nil {
		log.Printf("[AC1] ASCON解密失败")
		return
	}

	if len(PT) < 53 {
		log.Printf("[AC1] 解密后明文长度不足")
		return
	}

	SAC_AS1_2_extract := PT[0:2]
	B_extract := PT[2:35]
	UI_AC1_extract := PT[35:36]
	UI_AC2_extract := PT[36:37]
	N3 := PT[37:]

	if !bytesEqual(SAC_AS1_2_extract, uint12ToBytes(resp.SAC_AS1_2)) {
		log.Printf("[AC1] SAC_AS1_2不匹配")
		return
	}
	if !bytesEqual(UI_AC1_extract, uint8ToBytes(ac1.UI_AC1)) {
		log.Printf("[AC1] UI_AC1不匹配")
		return
	}
	if !bytesEqual(UI_AC2_extract, uint8ToBytes(ac1.UI_AC2)) {
		log.Printf("[AC1] UI_AC2不匹配")
		return
	}
	if !bytesEqual(N3, resp.Nonce) {
		log.Printf("[AC1] N3不匹配")
		return
	}

	N4 := make([]byte, 16)
	if _, err := rand.Read(N4); err != nil {
		log.Printf("[AC1] 生成N4失败: %v", err)
		return
	}

	N4Str := fmt.Sprintf("%x", N4)
	ac1.mutex.Lock()
	ac1.usedNonces[N4Str] = true
	ac1.mutex.Unlock()

	d, err := rand.Int(rand.Reader, ac1.n)
	if err != nil {
		log.Printf("[AC1] 生成随机数d失败: %v", err)
		return
	}

	D_x, D_y := ac1.curve.ScalarBaseMult(d.Bytes())
	D := elliptic.MarshalCompressed(ac1.curve, D_x, D_y)

	X_AC2_x, X_AC2_y := elliptic.UnmarshalCompressed(ac1.curve, ac1.X_AC2)
	Y_AC2_x, Y_AC2_y := elliptic.UnmarshalCompressed(ac1.curve, ac1.Y_AC2)
	if X_AC2_x == nil || Y_AC2_x == nil {
		log.Printf("[AC1] 解压缩AC2公钥失败")
		return
	}

	sum_x, sum_y := ac1.curve.Add(X_AC2_x, X_AC2_y, Y_AC2_x, Y_AC2_y)
	e_x, e_y := ac1.curve.ScalarMult(sum_x, sum_y, d.Bytes())

	h3_e := ac1.cryptoUtils.H3(e_x, e_y)

	data = constructData(ac1.UI_AC1, ac1.UA_AS1, resp.SAC_AS1_2, B_extract)
	if data == nil {
		fmt.Println("构造数据失败")
		return
	}

	f := xorBytes(h3_e, data)

	M4 := append(D, f...)

	crAucRqst2 := &message_types.CrAucRqst2{
		Stype:   0x64,
		Ver:     0x1,
		PID:     0x0,
		UI_AC1: ac1.UI_AC1,
		AUTHID:  0x1,
		ENCRID:  0x1,
		PAD:     0x0,
		Nonce:   N4,
		M4:      M4,
	}

	msg, err := util.MarshalLdacsPkt(crAucRqst2)

	if err != nil {
		logger.Error("Validation failed:", err)
	} else {
		logger.Info("Validation succeeded")
	}

	logger.Warn("Marshaled:", msg)

	ac1.sendToAC2(msg)
	fmt.Printf("[AC1] 已发送CR_AUC_RQST_2至AC2\n")
}

func (ac1 *AC1) sendToAC2(data []byte) {
	conn, err := net.Dial("tcp", "localhost:8001")
	if err != nil {
		log.Printf("[AC1]连接AC2失败: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		log.Printf("[AC1] 发送数据失败: %v", err)
	}
}

func (ac1 *AC1) asconEncrypt(key, nonce, ad, plaintext []byte) []byte {
	cipher, err := ascon.New(key, ascon.Ascon128)
	if err != nil {
		log.Printf("[AC1] 创建ASCON密码失败: %v", err)
		return nil
	}

	return cipher.Seal(nil, nonce, plaintext, ad)
}

func (ac1 *AC1) asconDecrypt(key, nonce, ad, ciphertext []byte) []byte {
	cipher, err := ascon.New(key, ascon.Ascon128)
	if err != nil {
		log.Printf("[AC1] 创建ASCON密码失败: %v", err)
		return nil
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		log.Printf("[AC1] ASCON解密失败: %v", err)
		return nil
	}

	return plaintext
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

func (ac1 *AC1) constructPlaintext(N1 []byte) []byte {

	P := make([]byte, 23)
	offset := 0

	P[offset] = ac1.UI_AC1
	offset++

	combined := uint64(ac1.UA_AS1&0x0FFFFFFF)<<12 | uint64(ac1.SAC_AS1&0x0FFF)

	P[offset] = byte((combined >> 32) & 0xFF)
	P[offset+1] = byte((combined >> 24) & 0xFF)
	P[offset+2] = byte((combined >> 16) & 0xFF)
	P[offset+3] = byte((combined >> 8) & 0xFF)
	P[offset+4] = byte(combined & 0xFF)
	offset += 5

	P[offset] = ac1.UI_AC2
	offset++

	copy(P[offset:], N1)

	return P
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

func constructData(UI_AC1 uint8, UA_AS1 uint32, SAC_AS1_2 uint16, B []byte) []byte {
	if len(B) != 33 {
		log.Printf("错误：B的长度必须为33字节，实际长度: %d", len(B))
		return nil
	}

	data := make([]byte, 39)
	offset := 0

	data[offset] = UI_AC1
	offset++

	UA_AS1_masked := uint64(UA_AS1 & 0x0FFFFFFF)
	SAC_AS1_2_masked := uint64(SAC_AS1_2 & 0x0FFF)

	combined := UA_AS1_masked<<12 | SAC_AS1_2_masked

	data[offset] = byte((combined >> 32) & 0xFF)
	data[offset+1] = byte((combined >> 24) & 0xFF)
	data[offset+2] = byte((combined >> 16) & 0xFF)
	data[offset+3] = byte((combined >> 8) & 0xFF)
	data[offset+4] = byte(combined & 0xFF)
	offset += 5

	copy(data[offset:], B)

	return data
}
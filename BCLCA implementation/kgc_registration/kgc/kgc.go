package kgc

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"fmt"
	"io/ioutil"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"encoding/hex"
	"gocode/kgc_registration/hash_utils"
	"gocode/kgc_registration/message_types"
)

type KGCParams struct {
	UI       string `json:"ui"`
	S        string `json:"s"`
	PubBytes string `json:"pub_bytes"`
	PubX     string `json:"pub_x"`
	PubY     string `json:"pub_y"`
}

type KGC struct {
	curve      elliptic.Curve
	p          *big.Int
	n          *big.Int
	Gx, Gy     *big.Int

	ui         []byte
	s          *big.Int
	PubX, PubY *big.Int
	PubBytes   []byte

	port            string
	usedNonces      map[string]bool
	publicKeys      map[string]KeyInfo
	currentSessions map[string]*SessionInfo

	cryptoUtils *hash_utils.CryptoUtils
	mutex       sync.RWMutex
	paramsFile string
}

type SessionInfo struct {
	UA []byte
	X  []byte
}

type KeyInfo struct {
	X string
	Y string
}

func NewKGC(port string) *KGC {
	curve := elliptic.P256()
	params := curve.Params()

	kgc := &KGC{
		curve:           curve,
		p:               params.P,
		n:               params.N,
		Gx:              params.Gx,
		Gy:              params.Gy,

		port:            port,
		usedNonces:      make(map[string]bool),
		publicKeys:      make(map[string]KeyInfo),
		currentSessions: make(map[string]*SessionInfo),
		cryptoUtils:     &hash_utils.CryptoUtils{},
		paramsFile:      "kgc_params.json",
	}

	if err := kgc.loadOrGenerateParams(); err != nil {
		log.Fatal("初始化KGC参数失败:", err)
	}

	fmt.Println("\n=== KGC系统初始化完成 ===")
	fmt.Printf("参数来源: %s\n", kgc.getParamsSource())
	fmt.Printf("Fq: Prime Field for P-256\n")
	fmt.Printf("ui: %x\n", kgc.ui)
	fmt.Printf("s: %x\n", kgc.s)
	fmt.Printf("p: %x\n", kgc.p)
	fmt.Printf("n: %x\n", kgc.n)
	fmt.Printf("P_pub: %x\n", kgc.PubBytes)
	fmt.Println("哈希函数: h1(Zq*), h2(SHA3-512), h3(SHAKE-128)")
	fmt.Println("=" + fmt.Sprintf("%50s", ""))

	return kgc
}

func (kgc *KGC) loadOrGenerateParams() error {

	if _, err := os.Stat(kgc.paramsFile); os.IsNotExist(err) {

		return kgc.generateAndSaveParams()
	}

	if err := kgc.loadParams(); err != nil {
		log.Printf("加载参数失败，将生成新参数: %v", err)
		return kgc.generateAndSaveParams()
	}

	return nil
}

func (kgc *KGC) loadParams() error {

	data, err := ioutil.ReadFile(kgc.paramsFile)
	if err != nil {
		return fmt.Errorf("读取参数文件失败: %v", err)
	}

	var params KGCParams
	if err := json.Unmarshal(data, &params); err != nil {
		return fmt.Errorf("解析参数文件失败: %v", err)
	}

	var ok bool

	uiBytes, err := hex.DecodeString(params.UI)
	if err != nil || len(uiBytes) != 1 {
		return fmt.Errorf("解析唯一标识UI失败: %v", err)
	}
	kgc.ui = uiBytes

	kgc.s, ok = new(big.Int).SetString(params.S, 16)
	if !ok {
		return fmt.Errorf("解析主私钥s失败")
	}

	kgc.PubX, ok = new(big.Int).SetString(params.PubX, 16)
	if !ok {
		return fmt.Errorf("解析主公钥X坐标失败")
	}

	kgc.PubY, ok = new(big.Int).SetString(params.PubY, 16)
	if !ok {
		return fmt.Errorf("解析主公钥Y坐标失败")
	}

	pubBytesHex := params.PubBytes
	if len(pubBytesHex)%2 != 0 {
		return fmt.Errorf("主公钥字节长度不正确")
	}

	kgc.PubBytes = make([]byte, len(pubBytesHex)/2)
	for i := 0; i < len(pubBytesHex); i += 2 {
		var b byte
		if _, err := fmt.Sscanf(pubBytesHex[i:i+2], "%02x", &b); err != nil {
			return fmt.Errorf("解析主公钥字节失败: %v", err)
		}
		kgc.PubBytes[i/2] = b
	}

	if !kgc.validateParams() {
		return fmt.Errorf("参数验证失败")
	}

	fmt.Println("[KGC] 成功加载已有参数")
	return nil
}

func (kgc *KGC) generateAndSaveParams() error {

	var err error
	kgc.s, err = rand.Int(rand.Reader, kgc.n)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %v", err)
	}

	kgc.PubX, kgc.PubY = kgc.curve.ScalarBaseMult(kgc.s.Bytes())
	kgc.PubBytes = elliptic.MarshalCompressed(kgc.curve, kgc.PubX, kgc.PubY)

	uiBytes := make([]byte, 1)
	if _, err := rand.Read(uiBytes); err != nil {
		return fmt.Errorf("生成UI失败: %v", err)
	}
	kgc.ui = uiBytes

	params := KGCParams{
		UI:       hex.EncodeToString(kgc.ui),
		S:        kgc.s.Text(16),
		PubBytes: fmt.Sprintf("%x", kgc.PubBytes),
		PubX:     kgc.PubX.Text(16),
		PubY:     kgc.PubY.Text(16),
	}

	data, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化参数失败: %v", err)
	}

	dir := filepath.Dir(kgc.paramsFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	if err := ioutil.WriteFile(kgc.paramsFile, data, 0600); err != nil {
		return fmt.Errorf("保存参数文件失败: %v", err)
	}

	fmt.Println("[KGC] 生成并保存新参数")
	return nil
}

func (kgc *KGC) validateParams() bool {

	expectedX, expectedY := kgc.curve.ScalarBaseMult(kgc.s.Bytes())
	if kgc.PubX.Cmp(expectedX) != 0 || kgc.PubY.Cmp(expectedY) != 0 {
		return false
	}

	expectedBytes := elliptic.MarshalCompressed(kgc.curve, kgc.PubX, kgc.PubY)
	if len(kgc.PubBytes) != len(expectedBytes) {
		return false
	}

	for i, b := range kgc.PubBytes {
		if b != expectedBytes[i] {
			return false
		}
	}

	return true
}

func (kgc *KGC) getParamsSource() string {
	if _, err := os.Stat(kgc.paramsFile); os.IsNotExist(err) {
		return "新生成"
	}
	return "从文件加载"
}

func (kgc *KGC) ResetParams() error {

	if err := os.Remove(kgc.paramsFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除旧参数文件失败: %v", err)
	}

	return kgc.generateAndSaveParams()
}

func (kgc *KGC) Start() {
	listener, err := net.Listen("tcp", kgc.port)
	if err != nil {
		log.Fatal("启动服务器失败:", err)
	}
	defer listener.Close()

	fmt.Printf("[KGC] 监听端口 %s\n", kgc.port[1:])

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go kgc.handleConnection(conn)
	}
}

func (kgc *KGC) handleConnection(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Printf("[KGC] 读取数据失败 from %s: %v", addr, err)
		}
		return
	}

	data := buffer[:n]
	if len(data) == 0 {
		return
	}

	msgType := data[0]
	switch msgType {
	case message_types.MSG_REG_RQST:
		kgc.handleRegRqst(conn, addr, data)
	case message_types.MSG_UPLOAD:
		kgc.handleUpload(conn, addr, data)
	default:
		log.Printf("[KGC] 未知消息类型: %d from %s", msgType, addr)
	}
}

func (kgc *KGC) handleRegRqst(_ net.Conn, addr string, data []byte) {
	msg, err := message_types.DeserializeRegRqst(data)
	if err != nil {
		log.Printf("[KGC] 反序列化REG_RQST失败 from %s: %v", addr, err)
		return
	}

	fmt.Printf("[KGC] 收到来自 %s 实体%s的消息: REG_RQST\n", addr, msg.Entity)

	nonceStr := fmt.Sprintf("%x", msg.Nonce)
	kgc.mutex.Lock()
	if kgc.usedNonces[nonceStr] {
		kgc.mutex.Unlock()
		log.Printf("[KGC] N1已使用: %s", nonceStr)
		return
	}
	kgc.usedNonces[nonceStr] = true
	kgc.mutex.Unlock()

	if len(msg.M1) < 37 {
		log.Printf("[KGC] M1长度不正确: %d", len(msg.M1))
		return
	}

	uaExtract := msg.M1[:4]
	XExtract := msg.M1[4:]

	sessionKey := msg.Entity
	kgc.mutex.Lock()
	kgc.currentSessions[sessionKey] = &SessionInfo{
		UA: uaExtract,
		X:  XExtract,
	}
	kgc.mutex.Unlock()

	N2 := make([]byte, 16)
	if _, err := rand.Read(N2); err != nil {
		log.Printf("[KGC] 生成N2失败: %v", err)
		return
	}

	N2Str := fmt.Sprintf("%x", N2)
	kgc.mutex.Lock()
	kgc.usedNonces[N2Str] = true
	kgc.mutex.Unlock()

	r, err := rand.Int(rand.Reader, kgc.n)
	if err != nil {
		log.Printf("[KGC] 生成随机数r失败: %v", err)
		return
	}

	Rx, Ry := kgc.curve.ScalarBaseMult(r.Bytes())
	RBytes := elliptic.MarshalCompressed(kgc.curve, Rx, Ry)

	H := kgc.cryptoUtils.H2(uaExtract, XExtract, RBytes, kgc.PubBytes)

	sH := new(big.Int).Mul(kgc.s, H)
	y := new(big.Int).Add(r, sH)
	y.Mod(y, kgc.n)

	regResp := &message_types.RegRespMsg{
		Type:   message_types.MSG_REG_RESP,
		Entity: "KGC",
		Nonce:  N2,
		PPub:   kgc.PubBytes,
		Y:      y,
		R:      RBytes,
	}

	fmt.Printf("[KGC] 正在发送数据到entity: {'type': 'REG_RESP', 'entity': 'KGC', 'Nonce': '%x', 'P_pub': '%x', 'y': %s, 'R': '%x'}\n",
		N2, kgc.PubBytes, y.String(), RBytes)

	kgc.sendToEntity(regResp.Serialize(), ":6001")
	fmt.Printf("[KGC] 已发送REG_RESP至entity\n")
}

func (kgc *KGC) handleUpload(_ net.Conn, addr string, data []byte) {
	msg, err := message_types.DeserializeUpload(data)
	if err != nil {
		log.Printf("[KGC] 反序列化UPLOAD失败 from %s: %v", addr, err)
		return
	}

	fmt.Printf("[KGC] 收到来自 %s 实体%s的消息: UPLOAD\n", addr, msg.Entity)

	nonceStr := fmt.Sprintf("%x", msg.Nonce)
	kgc.mutex.Lock()
	if kgc.usedNonces[nonceStr] {
		kgc.mutex.Unlock()
		log.Printf("[KGC] N3已使用: %s", nonceStr)
		return
	}
	kgc.usedNonces[nonceStr] = true
	kgc.mutex.Unlock()

	sessionKey := msg.Entity
	kgc.mutex.RLock()
	session, exists := kgc.currentSessions[sessionKey]
	kgc.mutex.RUnlock()

	if !exists {
		log.Printf("[KGC] 找不到会话信息: %s", sessionKey)
		return
	}

	if !bytesEqual(msg.UA, session.UA) || !bytesEqual(msg.X, session.X) {
		log.Printf("[KGC] UA或X不匹配")
		return
	}

	fmt.Printf("[KGC]收到%s的公钥上传信息:\nUA:%x\nX:%x\nY:%x\n",
		msg.Entity, msg.UA, msg.X, msg.Y)

	uaStr := fmt.Sprintf("%x", msg.UA)
	kgc.mutex.Lock()
	kgc.publicKeys[uaStr] = KeyInfo{
		X: fmt.Sprintf("%x", msg.X),
		Y: fmt.Sprintf("%x", msg.Y),
	}

	delete(kgc.currentSessions, sessionKey)
	kgc.mutex.Unlock()
}

func (kgc *KGC) sendToEntity(data []byte, port string) {
	conn, err := net.Dial("tcp", "localhost"+port)
	if err != nil {
		log.Printf("[KGC] 连接到实体失败: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		log.Printf("[KGC] 发送数据失败: %v", err)
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
package entity

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
	"gocode/kgc_registration/hash_utils"
	"gocode/kgc_registration/message_types"
)

type Entity struct {
	curve       elliptic.Curve
	Gx, Gy      *big.Int 
	n           *big.Int 
	
	port        string
	usedNonces  map[string]bool
	
	ua          []byte
	x           *big.Int 
	y           *big.Int 
	s           *big.Int 
	X           []byte   
	Y           []byte   
	S           []byte  

	
	cryptoUtils *hash_utils.CryptoUtils
	mutex       sync.RWMutex
}

func NewEntity(port string) *Entity {
	curve := elliptic.P256()
	params := curve.Params()
	
	entity := &Entity{
		curve:        curve,
		Gx:           params.Gx,
		Gy:           params.Gy,
		n:            params.N,
		port:         port,
		usedNonces:   make(map[string]bool),
		cryptoUtils:  &hash_utils.CryptoUtils{},
	}
	
	return entity
}

func (e *Entity) Start() {
	go e.startServer()
	
	time.Sleep(100 * time.Millisecond)
	
	e.sendRegRqst()
}

func (e *Entity) startServer() {
	listener, err := net.Listen("tcp", e.port)
	if err != nil {
		log.Fatal("启动服务器失败:", err)
	}
	defer listener.Close()
	
	fmt.Printf("[entity] 监听端口 %s\n", e.port[1:]) 
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		
		go e.handleConnection(conn)
	}
}
func (e *Entity) handleConnection(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Printf("[entity] 读取数据失败 from %s: %v", addr, err)
		}
		return
	}
	
	data := buffer[:n]
	if len(data) == 0 {
		return
	}
	
	msgType := data[0]
	switch msgType {
	case message_types.MSG_REG_RESP:
		e.handleRegResp(conn, addr, data)
	default:
		log.Printf("[entity] 未知消息类型: %d from %s", msgType, addr)
	}
}

func (e *Entity) sendRegRqst() {
	N1 := make([]byte, 16)
	if _, err := rand.Read(N1); err != nil {
		log.Printf("[entity] 生成N1失败: %v", err)
		return
	}
	
	N1Str := fmt.Sprintf("%x", N1)
	e.mutex.Lock()
	e.usedNonces[N1Str] = true
	e.mutex.Unlock()
	
	uaBytes := make([]byte, 4)
	if _, err := rand.Read(uaBytes); err != nil {
		log.Printf("[entity] 生成UA失败: %v", err)
		return
	}
	e.ua = uaBytes
	
	x, err := rand.Int(rand.Reader, e.n)
	if err != nil {
		log.Printf("[entity] 生成私钥x失败: %v", err)
		return
	}
	e.x = x
	
	XPubX, XPubY := e.curve.ScalarBaseMult(x.Bytes())
	XBytes := elliptic.MarshalCompressed(e.curve, XPubX, XPubY)
	e.X = XBytes
	
	M1 := append(uaBytes, XBytes...)
	
	regRqst := &message_types.RegRqstMsg{
		Type:   message_types.MSG_REG_RQST,
		Entity: "entity",
		Nonce:  N1,
		M1:     M1,
	}
	
	fmt.Printf("[entity] 正在发送数据到KGC: {'type': 'REG_RQST', 'entity': 'entity', 'Nonce': '%x', 'M1': '%x'}\n",
		N1, M1)
	
	e.sendToKGC(regRqst.Serialize())
	fmt.Printf("[entity] 已发送REG_RQST至KGC\n")
}

func (e *Entity) handleRegResp(_ net.Conn, addr string, data []byte) {
	msg, err := message_types.DeserializeRegResp(data)
	if err != nil {
		log.Printf("[entity] 反序列化REG_RESP失败 from %s: %v", addr, err)
		return
	}
	
	fmt.Printf("[entity] 收到来自 %s 实体%s的消息: REG_RESP\n", addr, msg.Entity)
	
	nonceStr := fmt.Sprintf("%x", msg.Nonce)
	e.mutex.Lock()
	if e.usedNonces[nonceStr] {
		e.mutex.Unlock()
		log.Printf("[entity] N2已使用: %s", nonceStr)
		return
	}
	e.usedNonces[nonceStr] = true
	e.mutex.Unlock()
	
	PPubX, PPubY := elliptic.UnmarshalCompressed(e.curve, msg.PPub) 
	if PPubX == nil {
		log.Printf("[entity] 解析P_pub失败")
		return
	}
	
	RX, RY := elliptic.UnmarshalCompressed(e.curve, msg.R) 
	if RX == nil {
		log.Printf("[entity] 解析R失败")
		return
	}
	
	e.y = msg.Y 
	
	H := e.cryptoUtils.H2(e.ua, e.X, msg.R, msg.PPub)

	YGx, YGy := e.curve.ScalarBaseMult(msg.Y.Bytes())
	
	HPubX, HPubY := e.curve.ScalarMult(PPubX, PPubY, H.Bytes())
	
	expectedX, expectedY := e.curve.Add(RX, RY, HPubX, HPubY)
	
	if YGx.Cmp(expectedX) == 0 && YGy.Cmp(expectedY) == 0 {
		e.Y = elliptic.MarshalCompressed(e.curve, YGx, YGy)
        XGx, XGy := elliptic.UnmarshalCompressed(e.curve, e.X)
        if XGx == nil || XGy == nil {
            log.Printf("[entity] 解压缩公钥X失败")
            return
        }
		e.s = new(big.Int).Add(e.x, e.y)
		e.s.Mod(e.s, e.n)
		SGx, SGy := e.curve.ScalarBaseMult(e.s.Bytes())
		e.S = elliptic.MarshalCompressed(e.curve, SGx, SGy)

		YGx, YGy := elliptic.UnmarshalCompressed(e.curve, e.Y)
		if YGx == nil || YGy== nil {
			log.Printf("[entity] 解压缩公钥Y失败")
			return
		}

		fmt.Printf("[entity]实体注册成功: \nUA:%x\nx:%x\ny:%x\nX:%x\nXx=%x\nXy=%x\nY:%x\nYx=%x\nYy=%x\n",
			e.ua, e.x, e.y, e.X, XGx, XGy, e.Y, YGx, YGy, )
		e.sendUpload()
	} else {
		log.Printf("[entity] 验证失败")
	}
}

func (e *Entity) sendUpload() {
	N3 := make([]byte, 16)
	if _, err := rand.Read(N3); err != nil {
		log.Printf("[entity] 生成N3失败: %v", err)
		return
	}
	
	N3Str := fmt.Sprintf("%x", N3)
	e.mutex.Lock()
	e.usedNonces[N3Str] = true
	e.mutex.Unlock()

	upload := &message_types.UploadMsg{
		Type:   message_types.MSG_UPLOAD,
		Entity: "entity",
		Nonce:  N3,
		UA:     e.ua,
		X:      e.X, 
		Y:      e.Y, 
	}
	
	fmt.Printf("[entity] 正在发送数据到KGC: {'type': 'UPLOAD', 'entity': 'entity', 'Nonce': '%x', 'UA': '%x', 'X': '%x', 'Y': '%x'}\n",
		N3, e.ua, e.X, e.Y)
	
	e.sendToKGC(upload.Serialize())
	fmt.Printf("[entity] 已发送UPLOAD至KGC\n")
}

func (e *Entity) sendToKGC(data []byte) {
	conn, err := net.Dial("tcp", "localhost:6000") 
	if err != nil {
		log.Printf("[entity] 连接到KGC失败: %v", err)
		return
	}
	defer conn.Close()
	
	_, err = conn.Write(data)
	if err != nil {
		log.Printf("[entity] 发送数据失败: %v", err)
		return
	}
}

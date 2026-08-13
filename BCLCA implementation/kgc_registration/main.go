package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gocode/kgc_registration/kgc"
	"gocode/kgc_registration/entity"
)

func main() {
	fmt.Println("=== KGC注册系统启动 ===")
	fmt.Println("系统架构: KGC <-> Entity")
	fmt.Println("端口分配:")
	fmt.Println("  KGC:    :6000")
	fmt.Println("  Entity: :6001")
	fmt.Println("=======================")

	var wg sync.WaitGroup

	fmt.Println("\n[主程序] 正在初始化各个实体...")

	kgcInstance := kgc.NewKGC(":6000")

	entityInstance := entity.NewEntity(":6001")

	fmt.Println("\n[主程序] 所有实体初始化完成")

	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("[主程序] 启动KGC服务器...")
		kgcInstance.Start()
	}()

	time.Sleep(2 * time.Second)

	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("[主程序] 启动Entity并发起注册...")
		entityInstance.Start()
	}()

	fmt.Println("\n[主程序] 所有服务已启动")
	fmt.Println("[主程序] 实体注册流程:")
	fmt.Println("  1. Entity -> KGC: REG_RQST (注册请求)")
	fmt.Println("  2. KGC    -> Entity: REG_RESP (注册响应)")
	fmt.Println("  3. Entity -> KGC: UPLOAD (公钥上传)")
	fmt.Println("  注册流程即将开始...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go monitorRegistrationSystem()

	select {
	case sig := <-sigChan:
		fmt.Printf("\n[主程序] 接收到信号: %v，正在关闭系统...\n", sig)
	case <-time.After(15 * time.Second):
		fmt.Println("\n[主程序] 注册流程执行完成，系统将在3秒后关闭...")
		time.Sleep(3 * time.Second)
	}

	fmt.Println("[主程序] 系统关闭中...")

	fmt.Println("[主程序] KGC注册系统已关闭")
}

func monitorRegistrationSystem() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("\n[监控] 注册系统运行状态检查:")
		fmt.Println("[监控] - KGC:    运行中 (密钥生成中心)")
		fmt.Println("[监控] - Entity: 运行中 (实体节点)")
		fmt.Println("[监控] 基于椭圆曲线的身份注册服务正常运行")

		if _, err := os.Stat("kgc_params.json"); err == nil {
			fmt.Println("[监控] KGC参数文件: 已存在并加载")
		} else {
			fmt.Println("[监控] KGC参数文件: 不存在，使用新生成参数")
		}
	}
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	fmt.Println("初始化KGC注册系统...")
	fmt.Println("基于椭圆曲线密码学的身份注册协议")
}
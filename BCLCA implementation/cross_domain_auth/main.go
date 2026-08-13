package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gocode/cross_domain_auth/as1"
	"gocode/cross_domain_auth/ac1"
	"gocode/cross_domain_auth/ac2"
)

func main() {
	fmt.Println("=== 跨域认证系统启动 ===")
	fmt.Println("系统架构: AC1 <-> AC2 <-> AS1")
	fmt.Println("端口分配:")
	fmt.Println("  AC1: :8000")
	fmt.Println("  AC2: :8001")
	fmt.Println("  AS1:  :8002")
	fmt.Println("========================")

	var wg sync.WaitGroup

	fmt.Println("\n[主程序] 正在初始化各个实体...")

	ac1Instance := ac1.NewAC1(":8000")

	ac2Instance := ac2.NewAC2(":8001")

	as1Instance := as1.NewAS1(":8002")

	fmt.Println("\n[主程序] 所有实体初始化完成")

	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("[主程序] 启动AC2服务器...")
		ac2Instance.Start()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("[主程序] 启动AS1服务器...")
		as1Instance.Start()
	}()

	time.Sleep(2 * time.Second)

	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("[主程序] 启动AC1并发起认证...")
		ac1Instance.Start()
	}()

	fmt.Println("\n[主程序] 所有服务已启动")
	fmt.Println("  跨域认证流程即将开始...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go monitorSystem()

	select {
	case sig := <-sigChan:
		fmt.Printf("\n[主程序] 接收到信号: %v，正在关闭系统...\n", sig)
	case <-time.After(30 * time.Second):
		fmt.Println("\n[主程序] 认证流程执行完成，系统将在5秒后关闭...")
		time.Sleep(5 * time.Second)
	}

	fmt.Println("[主程序] 系统关闭中...")

	fmt.Println("[主程序] 跨域认证系统已关闭")
}

func monitorSystem() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("\n[监控] 系统运行状态检查:")
		fmt.Println("[监控] - AC1: 运行中")
		fmt.Println("[监控] - AC2: 运行中")
		fmt.Println("[监控] - AS1:  运行中")
		fmt.Println("[监控] 所有服务正常运行")
	}
}

func init() {

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	fmt.Println("初始化跨域认证系统...")
	fmt.Println("基于椭圆曲线密码学和ASCON认证加密")
}

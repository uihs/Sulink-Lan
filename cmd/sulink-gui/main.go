// Sulink Lan 图形客户端入口。
//
// 设计目标：开箱即用——双击 exe 即出现窗口，无需命令行参数、无需手动放 dll。
//
// 启动流程：
//  1. 释放内嵌的 wintun.dll（虚拟网卡驱动，见 client.EnsureWintunDLL）
//  2. 检查管理员权限：创建虚拟网卡需要提权，缺失时给出明确提示而非静默失败
//  3. 进入图形界面主循环
//
// 命令行参数（通常由安装包/自启注册表传入，用户无需关心）：
//
//	-autostart   开机自启模式（仅启动界面，不抢占前台焦点）
//	-debug       开启 WebView2 调试模式（F12 开发者工具、右键菜单）
//	-version     打印版本后退出
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"sulink-lan/internal/gui"
)

func main() {
	autostart := flag.Bool("autostart", false, "开机自启模式")
	debug := flag.Bool("debug", false, "开启界面调试模式")
	version := flag.Bool("version", false, "打印版本后退出")
	logPath := flag.String("log", "", "日志文件路径（留空输出到 stderr）")
	flag.Parse()

	// 图形客户端以 -H windowsgui 编译（避免多出一个控制台黑窗口），
	// 因此从命令行启动时要先把父控制台接回来，-version 与启动错误才看得见。
	// 双击启动时无父控制台，此调用静默返回。
	gui.AttachParentConsole()

	if *version {
		fmt.Printf("Sulink Lan %s\n", gui.Version())
		return
	}

	// 日志：GUI 程序没有控制台，默认写到用户目录，便于排查问题
	if *logPath == "" {
		if p, err := gui.DefaultLogPath(); err == nil {
			if f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				defer f.Close()
				log.SetOutput(f)
				defer log.Printf("=== 启动 Sulink Lan %s ===", gui.Version())
			}
		}
	}

	// 1) 虚拟网卡驱动
	if err := gui.EnsureWintun(); err != nil {
		log.Printf("[main] wintun 初始化失败: %v", err)
		gui.Fatal("缺少虚拟网卡驱动", err.Error()+"\n\n请尝试重新安装 Sulink Lan。")
		return
	}

	// 2) 管理员权限
	if !gui.IsElevated() {
		log.Printf("[main] 未以管理员权限运行")
		gui.Fatal("需要管理员权限",
			"Sulink Lan 需要创建虚拟网卡，必须以管理员权限运行。\n\n"+
				"请右键点击程序图标，选择「以管理员身份运行」。\n"+
				"安装包安装的版本已自动配置为请求提权，通常不会看到此提示。")
		return
	}

	// 3) 图形界面
	_ = autostart // 预留：自启模式下可静默启动到托盘
	if err := gui.RunWithOptions(gui.Options{Debug: *debug}); err != nil {
		log.Printf("[main] 界面启动失败: %v", err)
		gui.Fatal("无法启动界面", err.Error())
	}
}

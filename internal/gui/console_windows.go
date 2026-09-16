//go:build windows

package gui

import (
	"os"
	"syscall"
)

// AttachParentConsole 尝试附着到父进程的控制台，让标准输出重新可用。
//
// 为什么需要：图形客户端用 -H windowsgui 编译（否则会多出一个控制台黑窗口，
// 即用户看到的「开了两个窗口，其中一个是黑屏」）。但这样一来，
// 从 cmd / PowerShell 启动时本该打印到终端的输出（-version、启动失败原因）
// 会全部石沉大海，命令行排查手段直接失效。
//
// 双击启动时不存在父控制台，AttachConsole 返回 0，函数静默返回，不影响正常使用。
func AttachParentConsole() {
	const attachParentProcess = ^uintptr(0) // (DWORD)-1
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	if r, _, _ := kernel32.NewProc("AttachConsole").Call(attachParentProcess); r == 0 {
		return
	}
	// 附着成功后要重新打开 CONOUT$：Go 进程启动时标准句柄是无效的，
	// 仅附着控制台并不会让 os.Stdout 自动可用。
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = f
		os.Stderr = f
	}
}

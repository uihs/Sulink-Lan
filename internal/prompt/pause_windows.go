//go:build windows

package prompt

import (
	"bufio"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// kernel32.GetConsoleProcessList 未在 x/sys/windows 中导出，
// 用懒加载直接取。
var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcList = kernel32.NewProc("GetConsoleProcessList")
)

// IsDoubleClickLaunch 判断进程是否由「双击」启动。
//
// 原理：双击运行时资源管理器为进程新建控制台，该控制台里只有
// 本进程；而从已有终端（cmd / PowerShell）启动时，控制台里
// 还挂着父 shell，进程数 >= 2。
//
// 用途：双击场景下程序退出会瞬间关闭窗口，用户来不及看任何输出。
// 识别出这种情况后，在退出前停留等待按键。
func IsDoubleClickLaunch() bool {
	buf := make([]uint32, 64)
	// GetConsoleProcessList(lpdwProcessList, dwProcessCount)
	// 返回写入的进程数；失败返回 0。
	n, _, _ := procGetConsoleProcList.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	// 控制台里只有自己 → 双击启动
	return n == 1
}

// PauseIfDoubleClick 若判断为双击启动，则提示并等待用户按回车。
//
// 只在双击场景下暂停：从 cmd/PowerShell 运行时不该多此一举地卡住，
// 否则脚本化调用会被挂起。
func PauseIfDoubleClick() {
	if !IsDoubleClickLaunch() {
		return
	}
	fmt.Fprint(os.Stderr, "\n按回车键关闭窗口…")
	r := bufio.NewReader(os.Stdin)
	_, _ = r.ReadString('\n')
}

//go:build windows

package prompt

import (
	"golang.org/x/sys/windows"
)

// isTerminal 判断句柄是否连着控制台。
//
// GetConsoleMode 只对控制台句柄成功；重定向到文件/管道时返回
// ERROR_INVALID_HANDLE，据此判定为非终端。
func isTerminal(fd uintptr) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}

// disableEcho 关闭控制台回显，返回恢复函数。
//
// 只关 ENABLE_ECHO_INPUT，其余标志保持不动：
//
//   - ENABLE_LINE_INPUT 必须保留。上层用 ReadString('\n') 按行读取，
//     这个模式正是「回车才交付一行」的来源。一旦关掉它，回车不再产生
//     换行符，读取会永久阻塞——表现为「能打字但按回车没反应」。
//   - ENABLE_PROCESSED_INPUT 也保留：关掉后 Ctrl+C 不再是信号，
//     用户在录入阶段想取消都取消不了。
//
// 关掉回显本身不影响行模式，两者是独立的标志位。
func disableEcho(fd uintptr) (func(), error) {
	h := windows.Handle(fd)
	var old uint32
	if err := windows.GetConsoleMode(h, &old); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(h, echoOff(old)); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, old) }, nil
}

// echoOff 计算「关闭回显」后的控制台模式。
//
// 抽成纯函数是为了可测：控制台模式是 Windows 独有能力，
// 而这类「关错标志导致读取永久阻塞」的问题一旦漏测，
// 只有在真机上手动敲键盘才暴露得出来。
func echoOff(mode uint32) uint32 {
	return mode &^ uint32(windows.ENABLE_ECHO_INPUT)
}

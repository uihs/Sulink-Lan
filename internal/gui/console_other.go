//go:build !windows

package gui

// AttachParentConsole 在非 Windows 平台无需处理：图形客户端在这些平台上
// 本来就带控制台，标准输出一直可用。保留同名函数只为让 main 的调用跨平台一致。
func AttachParentConsole() {}

//go:build !windows

package prompt

// IsDoubleClickLaunch 非 Windows 平台没有「双击导致窗口消失」的问题：
// 终端由用户自己启动，程序退出后终端仍在。
func IsDoubleClickLaunch() bool { return false }

// PauseIfDoubleClick 非 Windows 平台为空操作。
func PauseIfDoubleClick() {}

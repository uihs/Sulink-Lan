//go:build !windows

package gui

func isElevated() bool { return false }

// IsElevated 非 Windows 平台无此概念。
func IsElevated() bool { return false }

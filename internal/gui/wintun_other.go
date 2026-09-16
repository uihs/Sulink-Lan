//go:build !windows

package gui

// EnsureWintun 在非 Windows 平台无需释放 dll。
func EnsureWintun() error { return nil }

//go:build !windows

package gui

// 非 Windows 平台占位：GUI 目前只在 Windows 上构建（见 app.go 的 build tag）。
// 保留此文件是为了让 `go vet ./...` 在开发机上不因缺失符号而失败。
func setAutoStart(bool) error { return nil }

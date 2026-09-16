//go:build !windows

// 非 Windows 平台占位：GUI 仅支持 Windows。
// 保留最小实现，使 `go build ./...` 在其他平台的开发者机器上也能通过。
package gui

import "errors"

// Version 返回客户端版本号。
func Version() string { return appVersion }

// Options 启动选项。
type Options struct {
	Debug bool
}

// RunWithOptions 在非 Windows 平台不可用。
func RunWithOptions(Options) error {
	return errors.New("图形界面仅支持 Windows")
}

// DefaultLogPath 返回默认日志路径。
func DefaultLogPath() (string, error) { return "", errors.New("not supported") }

// Fatal 打印错误后退出。
func Fatal(title, msg string) { panic(title + ": " + msg) }

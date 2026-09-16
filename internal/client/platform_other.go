//go:build !windows

package client

// PreparePlatform 在非 Windows 平台无需额外准备。
// Linux 需要 root 才能打开 /dev/net/tun（错误会在 OpenTun 时给出）。
// macOS 同理需要 sudo。
func PreparePlatform() (func(), error) { return func() {}, nil }

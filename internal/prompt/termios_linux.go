//go:build linux || android

package prompt

import (
	"golang.org/x/sys/unix"
)

// Linux/Android 的 termios ioctl 常量是 TCGETS / TCSETS。
// 与 BSD/macOS 不同，必须按平台分开，不能共用一份实现。

func ioctlGetTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TCGETS)
}

func ioctlSetTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}

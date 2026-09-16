//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package prompt

import (
	"golang.org/x/sys/unix"
)

// BSD/macOS 的 termios ioctl 常量是 TIOCGETA / TIOCSETA，
// 与 Linux 的 TCGETS / TCSETS 不同名。
//
// 历史原因：这部分来自 BSD 的旧 tty 接口，
// Linux 后来采用了 System V 风格的命名。

func ioctlGetTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TIOCGETA)
}

func ioctlSetTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TIOCSETA, t)
}

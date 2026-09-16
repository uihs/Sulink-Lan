//go:build !windows

package prompt

import "golang.org/x/sys/unix"

// isTerminal 判断 fd 是否连着终端。
//
// 用「能否取到 termios」作判据：该 ioctl 只在 tty 设备上成功，
// 重定向到文件/管道时返回 ENOTTY。
func isTerminal(fd uintptr) bool {
	_, err := ioctlGetTermios(int(fd))
	return err == nil
}

// disableEcho 关闭终端回显，返回恢复函数。
//
// 返回闭包而非原始属性：各平台的属性类型不同
// （Unix 是 *Termios，Windows 是 uint32），
// 用闭包把差异收在平台文件内部，调用方无需感知。
func disableEcho(fd uintptr) (func(), error) {
	old, err := ioctlGetTermios(int(fd))
	if err != nil {
		return nil, err
	}
	// 复制一份再改：old 要保留原值，不能就地修改。
	// 只关 ECHO，保留 ICANON（规范模式）——关掉 ICANON 会让
	// 终端失去退格等行编辑能力，用户体验反而变差。
	next := *old
	next.Lflag &^= unix.ECHO
	if err := ioctlSetTermios(int(fd), &next); err != nil {
		return nil, err
	}
	return func() { _ = ioctlSetTermios(int(fd), old) }, nil
}

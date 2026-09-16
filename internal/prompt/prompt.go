// Package prompt 终端交互输入（带隐藏回显）。
//
// 为什么不全用 golang.org/x/term：
// 该包会引入新依赖，而我们需要的能力很小（关掉回显、读一行、恢复）。
// 用已有的 golang.org/x/sys 直接操作终端属性，依赖零增长。
//
// 平台分离：Unix 走 termios，Windows 走 console mode。
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrNoTTY 当前环境没有可用终端（被重定向、后台服务、管道）。
//
// 这个错误必须显式暴露：若静默返回空串，服务端会以空密钥启动，
// 表面上"启动成功"，实际上所有客户端都连不上。
var ErrNoTTY = errors.New("当前环境没有可用终端")

// IsTerminal 判断 fd 是否连着终端。
func IsTerminal(fd uintptr) bool { return isTerminal(fd) }

// StdinIsTerminal 判断标准输入是否为终端。
//
// 用途：决定能否走交互式输入。无法判断时保守返回 false，
// 让调用方走「明确报错」而非「读到一半卡住」的分支。
func StdinIsTerminal() bool { return isTerminal(os.Stdin.Fd()) }

// ReadSecret 提示用户输入一段隐藏回显的文本并回车。
//
// prompt 为提示文案；若输入流不是终端，返回 ErrNoTTY。
func ReadSecret(prompt string) (string, error) {
	fd := os.Stdin.Fd()
	if !isTerminal(fd) {
		return "", ErrNoTTY
	}

	// 提示语写到 stderr：避免用户把 stdout 重定向到文件时，
	// 提示语混进输出内容里。
	fmt.Fprint(os.Stderr, prompt)

	restore, err := disableEcho(fd)
	if err != nil {
		return "", err
	}
	// 无论读取是否出错，都必须恢复回显，
	// 否则用户后续在终端里输入的内容会一直不可见。
	defer func() {
		restore()
		fmt.Fprintln(os.Stderr)
	}()

	line, err := readLine()
	if err != nil {
		return "", err
	}
	return line, nil
}

// stdinReader 全局共享的缓冲读取器。
//
// 必须复用同一个 bufio.Reader：bufio 会一次读入远超一行的数据并缓存，
// 若每次 readLine 都新建 reader，第二次调用会拿到空串——
// 表现为「二次确认永远不一致」，而用户明明输入了相同内容。
// 这个坑在管道/pty 下必现，人工交互时因为输入是逐个键入的反而容易漏掉。
var stdinReader = bufio.NewReader(os.Stdin)

// readLine 读取一行（不含换行符）。
//
// 用 bufio 按行读而非逐字节读：Windows 下回车处理、
// 粘贴长文本、终端行编辑都交给系统与 bufio，少踩坑。
func readLine() (string, error) {
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		// 读到 EOF 但已有内容（例如用户没按回车就关掉输入）：
		// 视作输入完成，比直接报错更符合直觉。
		if errors.Is(err, io.EOF) && line != "" {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ReadSecretConfirmed 让用户输入两遍并要求一致。
//
// 为什么要二次确认：密钥输错一个字符，表现是"客户端全部连不上"，
// 而且服务端日志只显示认证失败，用户极难定位到自己当初手滑。
// 录入时确认一遍，代价远低于事后排查。
func ReadSecretConfirmed(prompt string) (string, error) {
	for attempt := 1; attempt <= 3; attempt++ {
		first, err := ReadSecret(prompt)
		if err != nil {
			return "", err
		}
		second, err := ReadSecret("请再输入一遍以确认: ")
		if err != nil {
			return "", err
		}
		if first == second {
			return first, nil
		}
		fmt.Fprintf(os.Stderr, "两次输入不一致，请重新输入（第 %d/3 次）\n\n", attempt)
	}
	return "", errors.New("连续 3 次输入不一致，已取消")
}

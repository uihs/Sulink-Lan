//go:build windows

package prompt

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestEchoOffKeepsLineInput 关键回归测试。
//
// 历史 bug：曾经在关闭回显时一并关掉了 ENABLE_LINE_INPUT，
// 导致上层按行读取（ReadString('\n')）永久阻塞，
// 用户表现为「能打字但按回车没反应」。
//
// 这个断言守住那条线：关回显只能动 ECHO 一个标志位。
func TestEchoOffKeepsLineInput(t *testing.T) {
	// 模拟一个正常的控制台输入模式
	mode := uint32(windows.ENABLE_PROCESSED_INPUT |
		windows.ENABLE_LINE_INPUT |
		windows.ENABLE_ECHO_INPUT)

	got := echoOff(mode)

	if got&windows.ENABLE_LINE_INPUT == 0 {
		t.Fatal("关闭回显时不能关掉 ENABLE_LINE_INPUT，否则回车无法结束输入行")
	}
	if got&windows.ENABLE_ECHO_INPUT != 0 {
		t.Fatal("ENABLE_ECHO_INPUT 应被清除")
	}
	// Ctrl+C 仍要可用，否则用户无法取消录入
	if got&windows.ENABLE_PROCESSED_INPUT == 0 {
		t.Fatal("不应关掉 ENABLE_PROCESSED_INPUT，否则 Ctrl+C 失效")
	}
}

// TestEchoOffIsolatesOnlyEcho 除 ECHO 外不得改动任何其他标志位。
func TestEchoOffIsolatesOnlyEcho(t *testing.T) {
	all := uint32(0xFFFF)
	got := echoOff(all)
	want := all &^ uint32(windows.ENABLE_ECHO_INPUT)
	if got != want {
		t.Fatalf("echoOff 只应清除 ECHO 位: got=%#x want=%#x", got, want)
	}
}

// TestEchoOffIdempotent 重复调用结果一致（便于恢复逻辑幂等）。
func TestEchoOffIdempotent(t *testing.T) {
	mode := uint32(windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT)
	once := echoOff(mode)
	twice := echoOff(once)
	if once != twice {
		t.Fatalf("echoOff 应幂等: once=%#x twice=%#x", once, twice)
	}
}

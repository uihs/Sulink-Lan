//go:build windows

package client

import (
	"testing"
	"unicode/utf8"
)

// TestDecodeNetshOutputRealBytes 用**真实字节**验证 netsh 输出的解码。
//
// 为什么必须喂字节而不是字符串：原有的 isBenignCommandError 用例全部传入
// 已经是 UTF-8 的中文字符串，绕开了真正的解码路径——所以旧测试全绿，
// 真机上却因为「UTF-8 被当 GBK 解」而匹配不上关键字、连接失败。
// 这类缺陷只有从字节开始测才拦得住。
func TestDecodeNetshOutputRealBytes(t *testing.T) {
	// 真机实测：Windows 10/11 的 netsh 输出 UTF-8。
	// 这两个字节串取自真实 netsh 输出（见注释中的中文字面量）。
	utf8Out := []byte("文件名、目录名或卷标语法不正确。")
	if !utf8.Valid(utf8Out) {
		t.Fatal("测试数据本身应是合法 UTF-8")
	}

	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"UTF-8 中文原样保留", utf8Out, "文件名、目录名或卷标语法不正确。"},
		{"UTF-8 找不到元素", []byte("找不到元素。"), "找不到元素。"},
		{"纯 ASCII 不变", []byte("The system cannot find the element specified."), "The system cannot find the element specified."},
		{"空输入", []byte{}, ""},
		// 反向对照：真正的 GBK 字节必须仍被正确解出，
		// 否则「回退 GBK」这条兼容路径就是假的。
		{"GBK 找不到元素回退", []byte{0xd5, 0xd2, 0xb2, 0xbb, 0xb5, 0xbd, 0xd4, 0xaa, 0xcb, 0xd8}, "找不到元素"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decodeNetshOutput(c.raw); got != c.want {
				t.Fatalf("decodeNetshOutput(% x) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

// TestBenignErrorSurvivesDecode 是端到端回归：真实的 UTF-8 字节 → 解码 →
// 判无害，必须一路走通。
//
// 这正是真机失败的路径。修复前：UTF-8 字节被 GBK 误解成乱码，
// 「找不到元素」匹配不上 → 返回 false → 幂等的删除步骤被当成真故障上抛，
// 表现为「删一个本来就不存在的地址，却导致连接失败」。
func TestBenignErrorSurvivesDecode(t *testing.T) {
	delCmd := PlatformCommand{"netsh", []string{"interface", "ip", "delete",
		"address", "name=Sulink Lan", "10.10.10.10"}}

	// netsh 删除不存在地址时输出的真实 UTF-8 字节
	raw := []byte("找不到元素。\r\n")
	if got := isBenignCommandError(delCmd, decodeNetshOutput(raw)); !got {
		t.Fatalf("UTF-8 的「找不到元素」解码后应判为无害，实际 false（"+
			"解码结果 %q）", decodeNetshOutput(raw))
	}

	// 反向对照：真故障必须仍然上抛——不能为了修这个 bug 而放宽判断。
	permRaw := []byte("请求的操作需要提升。\r\n")
	if got := isBenignCommandError(delCmd, decodeNetshOutput(permRaw)); got {
		t.Fatal("权限不足的错误绝不能判为无害")
	}
}


package hwid

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// fixedPath 返回一个总是给出同一路径的 path 函数（临时目录内）。
func fixedPath(t *testing.T) func() (string, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), idFileName)
	return func() (string, error) { return p, nil }
}

// TestComputePrefersMachineID 有平台机器标识时必须用它，且不落盘。
//
// 「不落盘」是这条断言的重点：若实现里先写文件再判断，
// 会在用户配置目录留下一个永远用不到的 hwid 文件，
// 日后平台标识读取修好了，那个旧文件反而可能被后续逻辑误用。
func TestComputePrefersMachineID(t *testing.T) {
	path := fixedPath(t)
	p, _ := path()

	got, err := compute(func() (string, bool) { return "machine-guid-abc", true }, path)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if !hex32.MatchString(got) {
		t.Fatalf("标识格式不对: %q", got)
	}
	if want := fingerprint("machine-guid-abc"); got != want {
		t.Fatalf("未按机器标识取值: got %q want %q", got, want)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("有机器标识时不应写兜底文件（stat err=%v）", err)
	}
}

// TestComputeIgnoresBlankMachineID 机器标识为空串/纯空白时视为「取不到」。
//
// 这是真实会遇到的形态：某些精简系统里注册表项存在但值为空。
// 若把它当成有效标识，所有这类机器会共用同一个 HWID，
// 服务端会把它们认成同一台设备、抢同一个 IP。
func TestComputeIgnoresBlankMachineID(t *testing.T) {
	path := fixedPath(t)
	for _, blank := range []string{"", "   ", "\t\n"} {
		got, err := compute(func() (string, bool) { return blank, true }, path)
		if err != nil {
			t.Fatalf("compute(%q): %v", blank, err)
		}
		if got == fingerprint(blank) {
			t.Fatalf("空机器标识被当成了有效值: %q", blank)
		}
	}
}

// TestComputeFallbackPersists 无机器标识时生成随机值并落盘，再次调用必须一致。
func TestComputeFallbackPersists(t *testing.T) {
	path := fixedPath(t)
	p, _ := path()
	none := func() (string, bool) { return "", false }

	first, err := compute(none, path)
	if err != nil {
		t.Fatalf("首次 compute: %v", err)
	}
	if !hex32.MatchString(first) {
		t.Fatalf("标识格式不对: %q", first)
	}

	// 文件里存的必须是原始随机值而不是指纹：指纹算法将来若调整，
	// 存指纹会让所有设备一次性换身份。存原始值则只是换个映射。
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("兜底文件未写入: %v", err)
	}
	raw := strings.TrimSpace(string(b))
	if raw == "" || raw == first {
		t.Fatalf("文件内容应为原始随机值，实际 %q", raw)
	}
	if got := fingerprint(raw); got != first {
		t.Fatalf("文件内容与返回标识不一致: %q -> %q, want %q", raw, got, first)
	}

	// 模拟进程重启：重新 compute（不带缓存）必须得到同一个标识
	second, err := compute(none, path)
	if err != nil {
		t.Fatalf("二次 compute: %v", err)
	}
	if second != first {
		t.Fatalf("重启后标识变了: %q -> %q", first, second)
	}
}

// TestComputeFallbackDistinct 不同机器的兜底标识必须不同。
func TestComputeFallbackDistinct(t *testing.T) {
	none := func() (string, bool) { return "", false }
	a, err := compute(none, fixedPath(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := compute(none, fixedPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("两台机器生成了相同标识: %q", a)
	}
}

// TestFingerprintHidesRaw 指纹必须与原始标识不同，且不同原始值不碰撞。
func TestFingerprintHidesRaw(t *testing.T) {
	const raw = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"
	got := fingerprint(raw)
	if strings.Contains(got, raw) || got == raw {
		t.Fatalf("指纹泄露了原始标识: %q", got)
	}
	if got == fingerprint(raw+"x") {
		t.Fatal("不同原始标识得到相同指纹")
	}
	// 同一原始值必须稳定（这是租约能绑定的前提）
	if got != fingerprint(raw) {
		t.Fatal("同一原始标识的指纹不稳定")
	}
}

// TestComputeEmptyFileRegenerates 兜底文件被清空时必须重新生成，而不是用空值。
func TestComputeEmptyFileRegenerates(t *testing.T) {
	path := fixedPath(t)
	p, _ := path()
	if err := os.WriteFile(p, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := compute(func() (string, bool) { return "", false }, path)
	if err != nil {
		t.Fatal(err)
	}
	if !hex32.MatchString(got) {
		t.Fatalf("空文件未被识别为「无标识」: %q", got)
	}
}

// TestIDRealMachine 在本机真实环境下取一次标识：验证平台分支确实能跑通。
//
// 把 APPDATA 指到临时目录，避免测试往用户真实配置目录写兜底文件。
func TestIDRealMachine(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	id, err := ID()
	if err != nil {
		t.Fatalf("ID(): %v", err)
	}
	if !hex32.MatchString(id) {
		t.Fatalf("标识格式不对: %q", id)
	}
	// 缓存生效：二次调用必须一致
	again, err := ID()
	if err != nil {
		t.Fatal(err)
	}
	if again != id {
		t.Fatalf("ID() 不稳定: %q -> %q", id, again)
	}
}

//go:build darwin

package hwid

import "testing"

// TestParseIOPlatformUUID 覆盖 ioreg 输出的解析。
// 只在 macOS 上编译执行，但解析逻辑与平台无关，这段样例输出是从真实
// ioreg 里摘的形态，回归时能直接对照。
func TestParseIOPlatformUUID(t *testing.T) {
	out := `+-o J316sAP  <class IOPlatformExpertDevice, id 0x1000001a0, registered, matched, active, busy 0 (0 ms), retain 8>
    {
      "IOPlatformUUID" = "0A1B2C3D-4E5F-6789-ABCD-EF0123456789"
      "IOPlatformSerialNumber" = "C02ABCDEFGHI"
      "manufacturer" = <"Apple Inc.">
    }`
	got, ok := parseIOPlatformUUID(out)
	if !ok {
		t.Fatal("未解析出 IOPlatformUUID")
	}
	if want := "0A1B2C3D-4E5F-6789-ABCD-EF0123456789"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// TestParseIOPlatformUUIDMissing 输出里没有该字段时必须报「取不到」，
// 让上层退回随机标识，而不是返回一个空字符串。
func TestParseIOPlatformUUIDMissing(t *testing.T) {
	if v, ok := parseIOPlatformUUID(`"IOPlatformSerialNumber" = "C02ABCDEFGHI"`); ok {
		t.Fatalf("不该解析出值: %q", v)
	}
}

package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSettingsRoundTrip 全局配置落盘后重载内容一致。
//
// 这是「公告保存在服务端，服务端重启后新上线设备也能看到」这条需求的底座：
// 配置只在内存里的话，重启一次公告就没了，而管理员不会知道要重发。
func TestSettingsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-config.json")
	in := map[string]string{"notice": "今晚 23:00 维护", "no_punch": "1"}
	if err := saveSettings(path, in); err != nil {
		t.Fatal(err)
	}
	got := loadSettings(path)
	if len(got) != 2 || got["notice"] != in["notice"] || got["no_punch"] != "1" {
		t.Fatalf("配置未正确往返: %+v", got)
	}
}

// TestLoadSettingsMissingFileIsEmpty 文件不存在是正常情况（首次启动），不是错误。
func TestLoadSettingsMissingFileIsEmpty(t *testing.T) {
	got := loadSettings(filepath.Join(t.TempDir(), "nope.json"))
	if len(got) != 0 {
		t.Fatalf("文件不存在时应返回空配置，实际 %+v", got)
	}
	// path 为空（测试/内存模式）同样返回空 map 而不是 nil，
	// 免得调用方在 nil map 上做 delete 之外的操作时 panic。
	if got := loadSettings(""); len(got) != 0 {
		t.Fatalf("空路径应返回空配置，实际 %+v", got)
	}
}

// TestLoadSettingsDropsEmptyValues 空值在加载时被丢弃。
//
// 落盘文件里若残留 "notice":""（例如有人手工编辑过），加载后应当与
// 「没有这一项」完全等价——否则客户端会收到一条空公告，
// 而管理页的「当前生效配置」会显示一个空条目。
func TestLoadSettingsDropsEmptyValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-config.json")
	raw := `{"version":1,"config":{"notice":"","no_punch":"1","other":"  "}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadSettings(path)
	if len(got) != 1 || got["no_punch"] != "1" {
		t.Fatalf("空值应被丢弃，实际 %+v", got)
	}
}

// TestLoadSettingsCorruptIsQuarantined 损坏的配置文件被隔离，服务端照常启动。
//
// 与设备表同样的取舍：一份坏掉的配置不该让服务器起不来，
// 但必须留证，否则「我的公告为什么没了」永远查不出原因。
func TestLoadSettingsCorruptIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-config.json")
	if err := os.WriteFile(path, []byte("[broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadSettings(path); len(got) != 0 {
		t.Fatalf("损坏文件应退化为空配置，实际 %+v", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() == "server-config.json" {
		t.Fatalf("损坏文件应被改名保留一份，目录内容: %v", entries)
	}
}

// TestSaveSettingsAtomicAndPrivate 落盘必须是「先写临时文件再改名」，且权限收紧。
//
// 直接覆盖写会在进程崩溃/断电时留下半截 JSON——那正好会被下一次启动
// 当成损坏文件隔离掉，等于一次崩溃就丢掉全部配置。
// 权限 0600 则是因为这个文件将来可能承载更多服务端策略。
func TestSaveSettingsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-config.json")
	if err := saveSettings(path, map[string]string{"notice": "hi"}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("写入后目录里只应有一个文件（临时文件必须已改名）: %v", entries)
	}
	// 权限 0600 只在类 Unix 系统上可断言：Windows 的 ACL 不会映射成 Unix 权限位，
	// os.Stat 一律报 0666，在那里断言这个只会得到一条无意义的失败。
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("配置权限应为 0600，实际 %v", fi.Mode().Perm())
		}
	}

	// 覆盖写同样只留下一个文件
	if err := saveSettings(path, map[string]string{"notice": "hi2"}); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("覆盖写后目录里仍只应有一个文件: %v", entries)
	}
	if got := loadSettings(path); got["notice"] != "hi2" {
		t.Fatalf("覆盖写未生效: %+v", got)
	}
}

// TestSortedKeysStable 键序稳定（落盘文件与「当前生效配置」的展示顺序都依赖它）。
func TestSortedKeysStable(t *testing.T) {
	got := sortedKeys(map[string]string{"notice": "a", "no_punch": "1", "alpha": "b"})
	want := []string{"alpha", "no_punch", "notice"}
	if len(got) != len(want) {
		t.Fatalf("键数不符: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("键序不符: %v，期望 %v", got, want)
		}
	}
	if len(sortedKeys(nil)) != 0 {
		t.Fatal("空 map 应返回空切片")
	}
}

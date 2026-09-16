package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// setTempAppData 把配置目录指向临时目录，避免测试污染真实用户配置。
func setTempAppData(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	return filepath.Join(dir, "SulinkLan", "config.json")
}

// TestLoadMissingReturnsDefaults 首次运行（无配置文件）必须返回可用默认值而非报错，
// 否则「开箱即用」会在第一次启动就失败。
func TestLoadMissingReturnsDefaults(t *testing.T) {
	path := setTempAppData(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("配置文件不存在时不应报错，得到: %v", err)
	}
	if cfg.Name == "" {
		t.Fatal("默认设备名不应为空")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("Load 不应创建配置文件")
	}
}

// TestSaveLoadRoundTrip 保存后读回必须一致。
func TestSaveLoadRoundTrip(t *testing.T) {
	setTempAppData(t)

	in := Config{
		Server:      "203.0.113.10:9000",
		Name:        "我的电脑",
		NoPunch:     true,
		AutoConnect: true,
		AutoStart:   true,
		// 设备凭证（自动注册签发）必须能完整落盘并读回
		DeviceID:   "dev-12345678",
		DeviceKey:  "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd",
		NetworkKey: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
	}
	if err := in.Save(); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	out, err := Load()
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if out.Server != in.Server || out.Name != in.Name {
		t.Fatalf("基础字段不一致: %+v", out)
	}
	if !out.NoPunch || !out.AutoConnect || !out.AutoStart {
		t.Fatalf("开关字段不一致: %+v", out)
	}
	if out.DeviceID != in.DeviceID || out.DeviceKey != in.DeviceKey || out.NetworkKey != in.NetworkKey {
		t.Fatalf("设备凭证未完整读回: %+v", out)
	}
}

// TestLoadToleratesUnknownAndMissingFields 版本演进兼容性：
// 旧版本配置缺字段、新版本配置多字段，都必须能读。
func TestLoadToleratesUnknownAndMissingFields(t *testing.T) {
	path := setTempAppData(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// 只有 server；额外字段 future_option 应被忽略
	body := `{"server":"1.2.3.4:9000","future_option":"ignored"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("宽松解析失败: %v", err)
	}
	if cfg.Server != "1.2.3.4:9000" {
		t.Fatalf("server 未读到: %s", cfg.Server)
	}
}

// TestLoadIgnoresLegacyForwardFields 旧配置里的本地穿透规则字段应被忽略并清除。
//
// 穿透规则改由服务端下发后，客户端不再有任何规则字段。磁盘上仍留着
// forward / forward_on 的老用户升级后必须能正常启动——不能因为多了两个
// 不认识的键就报「配置文件格式错误」，那会让升级直接不可用。
// 同时保存后这些键必须消失，避免用户误以为改它还能生效。
func TestLoadIgnoresLegacyForwardFields(t *testing.T) {
	path := setTempAppData(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"server":"1.2.3.4:9000","psk":"k","name":"n",` +
		`"forward":["8445=192.168.1.50:445"],"forward_on":false}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("含旧版本穿透字段的配置应能正常加载: %v", err)
	}
	if cfg.Server != "1.2.3.4:9000" || cfg.Name != "n" {
		t.Fatalf("其余字段应正常读取: %+v", cfg)
	}

	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{`"forward"`, `"forward_on"`, `"psk"`} {
		if bytes.Contains(data, []byte(gone)) {
			t.Fatalf("保存后的配置不应再包含 %s: %s", gone, data)
		}
	}
}

// TestLoadIgnoresLegacyAuthFields 旧配置里的认证字段（psk / reg_code）应被
// 宽松忽略并在保存后清除——认证已改为打开软件按设备标识自动注册，
// 但老用户磁盘上的旧键不能让他们升级后启动失败。
func TestLoadIgnoresLegacyAuthFields(t *testing.T) {
	path := setTempAppData(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"server":"1.2.3.4:9000","psk":"k","reg_code":"REG-CODE-123","name":"n"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("含旧版认证字段的配置应能正常加载: %v", err)
	}
	if cfg.Server != "1.2.3.4:9000" || cfg.Name != "n" {
		t.Fatalf("其余字段应正常读取: %+v", cfg)
	}

	// 覆写保存后不应再写出 psk / reg_code 键（字段已从结构体移除）
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{`"psk"`, `"reg_code"`} {
		if bytes.Contains(data, []byte(gone)) {
			t.Fatalf("保存后的配置不应再包含 %s: %s", gone, data)
		}
	}
}

// TestLoadIgnoresLegacyCIDRField 旧配置里的网段字段应被宽松忽略。
//
// 网段已固定为 protocol.VNetCIDR（不再是配置项），但大量用户磁盘上
// 还留着旧版本写入的 "cidr" 键。Load 不能因此报错——
// 用户升级后配置文件原样可用，才是不打断使用路径的正确行为。
func TestLoadIgnoresLegacyCIDRField(t *testing.T) {
	path := setTempAppData(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"server":"1.2.3.4:9000","psk":"k","name":"n","cidr":"10.10.0.0/16"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("含旧版 cidr 字段的配置应能正常加载: %v", err)
	}
	if cfg.Server != "1.2.3.4:9000" || cfg.Name != "n" {
		t.Fatalf("其余字段应正常读取: %+v", cfg)
	}

	// 覆写保存后不应再写出 cidr 键（字段已从结构体移除）
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"cidr"`)) {
		t.Fatalf("保存后的配置不应再包含 cidr 字段: %s", data)
	}
}

// TestLoadCorruptReturnsError 配置损坏时应报错（由调用方决定回落策略）。
func TestLoadCorruptReturnsError(t *testing.T) {
	path := setTempAppData(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("损坏的配置文件应当报错")
	}
}

// TestSaveIsAtomic 保存必须走「临时文件 + 改名」，
// 避免写入中途失败留下半截 JSON 导致下次启动读不出配置。
func TestSaveIsAtomic(t *testing.T) {
	path := setTempAppData(t)
	cfg := Default()
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("保存后不应残留临时文件")
	}
	// 覆写已有文件也应成功（Windows 上 Rename 到已存在文件的行为需验证）
	cfg.Name = "改名后"
	if err := cfg.Save(); err != nil {
		t.Fatalf("覆写失败: %v", err)
	}
	out, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != "改名后" {
		t.Fatalf("覆写未生效: %s", out.Name)
	}
}

// TestValidate 校验规则：拦截明显错误，放过合理值。
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"完整配置", Config{Server: "1.2.3.4:9000", Name: "n"}, false},
		{"域名服务器", Config{Server: "vpn.example.com:9000", Name: "n"}, false},
		{"缺服务器", Config{Name: "n"}, true},
		{"服务器缺端口", Config{Server: "1.2.3.4", Name: "n"}, true},
		{"缺设备名", Config{Server: "1.2.3.4:9000"}, true},
		{"空白字符不算填写", Config{Server: "   ", Name: "n"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

// TestDirCreatesDirectory Dir 必须确保目录存在（首次运行 Save 依赖它）。
func TestDirCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)

	got, err := Dir()
	if err != nil {
		t.Fatalf("Dir 失败: %v", err)
	}
	want := filepath.Join(dir, "SulinkLan")
	if got != want {
		t.Fatalf("Dir() = %s, 期望 %s", got, want)
	}
	if fi, err := os.Stat(got); err != nil || !fi.IsDir() {
		t.Fatalf("目录未创建: %v", err)
	}
}

// TestSaveFilePermission 配置文件含设备凭证，权限必须是 0600（仅属主可读写）。
func TestSaveFilePermission(t *testing.T) {
	path := setTempAppData(t)
	if err := (Config{DeviceKey: "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"}).Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows 不体现 Unix 权限位，仅在类 Unix 上断言
	if os.PathSeparator == '/' {
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("配置文件权限应为 0600，实际 %o", perm)
		}
	}
}

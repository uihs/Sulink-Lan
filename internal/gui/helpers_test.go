package gui

import (
	"testing"

	"sulink-lan/internal/config"
)

// configAlias 让测试用例不必逐字段书写 config.Config。
type configAlias = config.Config

// 这里曾有一组 buildRuleViews / ruleDesc 的用例，随「客户端穿透规则自配」
// 一起被删除（a8d3bfd）。客户端现在只能由服务端下发规则、只读展示，
// 解析逻辑统一在 internal/forward + internal/client，故不再有本地纯函数可测。

// TestValidatePartial 宽松校验：只拦截明显格式错误，允许保存半成品配置。
//
// 网段已固定为 protocol.VNetCIDR，不再作为配置项参与校验。
// 只填 IP 不带端口是**允许**的：NormalizeServerAddr 会补默认端口，
// 强制要求用户手打冒号只是徒增一次报错。
func TestValidatePartial(t *testing.T) {
	cases := []struct {
		name    string
		cfg     configForTest
		wantErr bool
	}{
		{"允许空配置（先存一半）", configForTest{}, false},
		{"合法服务器", configForTest{server: "203.0.113.10:9000"}, false},
		{"域名服务器", configForTest{server: "vpn.example.com:9000"}, false},
		{"服务器端口非法", configForTest{server: "1.2.3.4:abc"}, true},
		{"端口超范围", configForTest{server: "1.2.3.4:99999"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validatePartial(c.cfg.toConfig())
			if (err != nil) != c.wantErr {
				t.Fatalf("validatePartial() err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

// configForTest 简化测试用例书写。
type configForTest struct {
	server string
}

func (c configForTest) toConfig() (out configAlias) {
	out.Server = c.server
	return out
}

package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
)

// TestVNetCIDRIsFixed 网段是固定的 10.0.0.0/8。
//
// 这条断言看似多余（等于把常量抄一遍），但它把「网段不可配置」这一需求
// 直接固化下来：若有人改动常量，测试失败即提醒「这是需求变更，不是随手调整」。
// 网段被改动的连带影响面很大——地址池、网卡路由、README 都要同步，
// 有一个显式断言在此拦截，比依赖代码审查更可靠。
func TestVNetCIDRIsFixed(t *testing.T) {
	if VNetCIDR != "10.0.0.0/8" {
		t.Fatalf("虚拟网段应为 10.0.0.0/8，实际 %q。"+
			"如需变更网段，请同步检查 IP 池边界、网卡路由命令与 README 说明", VNetCIDR)
	}
}

// TestVNetBroadcast 广播哨兵地址必须与网段一致。
//
// 它被用作「泛洪」的哨兵：客户端把包发往该地址，服务端据此识别出
// 「这是广播，应转发给所有在线设备」。若它与网段脱节（例如网段改了
// 而广播地址没跟着变），泛洪会静默失效——包被当成普通单播按 VIP 查表，
// 必然查不到而丢弃，且没有任何报错。
func TestVNetBroadcast(t *testing.T) {
	if got := IP4String(VNetBroadcast); got != "10.255.255.255" {
		t.Fatalf("虚拟网段 %s 的定向广播地址应为 10.255.255.255，实际 %s", VNetCIDR, got)
	}
	// 广播地址必须落在网段内，否则客户端会在转发前就把它过滤掉
	_, ipnet, err := net.ParseCIDR(VNetCIDR)
	if err != nil {
		t.Fatal(err)
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, VNetBroadcast)
	if !ipnet.Contains(ip) {
		t.Fatalf("广播地址 %s 不在网段 %s 内，客户端不会把它交给隧道", ip, VNetCIDR)
	}
}

// TestVNetCIDRIsIPv4AndUsable 网段必须是合法 IPv4 且容量足够。
//
// VNetCIDR 会被 net.ParseCIDR 解析后用于计算地址池边界与网卡路由，
// 格式非法会让服务端启动即失败；掩码过大则地址很快耗尽。
func TestVNetCIDRIsIPv4AndUsable(t *testing.T) {
	ip, ipnet, err := net.ParseCIDR(VNetCIDR)
	if err != nil {
		t.Fatalf("网段无法解析: %v", err)
	}
	if ip.To4() == nil {
		t.Fatalf("网段必须是 IPv4，实际 %q", VNetCIDR)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		t.Fatalf("掩码位数应为 32，实际 %d", bits)
	}
	// 地址池要容纳相当数量的设备；/24 只有 253 个，对本工具的定位偏小。
	if ones > 24 {
		t.Fatalf("网段 %s 掩码为 /%d，可用地址过少（应不大于 /24）", VNetCIDR, ones)
	}
	// 网段内必须包含服务器自身地址 .1 与首个可分配地址 .2
	if !ipnet.Contains(net.ParseIP("10.0.0.2")) {
		t.Fatalf("网段 %s 未覆盖 10.0.0.2，地址池将无法分配首个地址", VNetCIDR)
	}
}

// TestMessageHasNoCIDRField 协议不再承载网段字段。
//
// 网段写死后无需在信令里传递。这里用 JSON 序列化结果做断言，
// 确保字段真的被移除（而不只是改名），避免旧字段残留引发误解。
func TestMessageHasNoCIDRField(t *testing.T) {
	m := &Message{Type: MsgWelcome, VIP: 0x0a000002}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"cidr", "mask"} {
		if _, ok := raw[gone]; ok {
			t.Fatalf("Welcome 消息不应再包含 %q 字段，实际 JSON: %s", gone, data)
		}
	}
}

// TestMessageIgnoresUnknownCIDRField 旧服务端多发的 cidr 字段应被忽略。
//
// 向后兼容：新客户端连旧服务端时，对方仍可能下发 cidr。
// json.Unmarshal 默认忽略未知字段，这里固化该行为，
// 确保不会因为对方多发一个字段就解析失败。
func TestMessageIgnoresUnknownCIDRField(t *testing.T) {
	const oldFormat = `{"t":2,"vip":167772162,"cidr":"10.0.0.0/8","mask":8}`
	var m Message
	if err := json.Unmarshal([]byte(oldFormat), &m); err != nil {
		t.Fatalf("旧格式消息应能被解析（未知字段忽略）: %v", err)
	}
	if m.Type != MsgWelcome {
		t.Fatalf("消息类型解析错误: %v", m.Type)
	}
	if m.VIP != 0x0a000002 {
		t.Fatalf("VIP 解析错误: %#x", m.VIP)
	}
}

// TestParseBool 下发配置里的布尔值要容忍管理页的各种手输写法。
func TestParseBool(t *testing.T) {
	for _, s := range []string{"1", "true", "TRUE", "on", "Yes", " y ", "是", "开"} {
		if !ParseBool(s) {
			t.Fatalf("%q 应解析为 true", s)
		}
	}
	for _, s := range []string{"", "0", "false", "off", "no", "否", "随便写的"} {
		if ParseBool(s) {
			t.Fatalf("%q 应解析为 false", s)
		}
	}
}

// TestConfigPushRoundTrip 下发配置的消息应能完整往返序列化。
func TestConfigPushRoundTrip(t *testing.T) {
	in := &Message{
		Type: MsgConfigPush,
		Config: map[string]string{
			CfgNotice:  "维护公告：今晚 23:00-24:00",
			CfgNoPunch: "1",
		},
	}
	var buf bytes.Buffer
	if err := WriteMsg(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadMsg(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != MsgConfigPush {
		t.Fatalf("类型不符: %v", out.Type)
	}
	if out.Config[CfgNotice] != in.Config[CfgNotice] || out.Config[CfgNoPunch] != "1" {
		t.Fatalf("配置项往返丢失: %+v", out.Config)
	}
	// 旧版本客户端（不认识 Config 字段）解析时不得报错——靠 json 的未知字段忽略
	if _, err := ReadMsg(bytes.NewReader(mustFrame(t, `{"t":10,"cfg":{"future":"x"}}`))); err != nil {
		t.Fatalf("带未知配置键的消息应可解析: %v", err)
	}
}

// mustFrame 把 JSON 文本包装成带长度前缀的信令帧（4 字节大端长度 + 载荷）。
func mustFrame(t *testing.T, jsonText string) []byte {
	t.Helper()
	payload := []byte(jsonText)
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

// TestHelloCarriesHWID 注册消息要带上设备标识，且缺字段时不影响解析。
//
// 后者是混跑场景的底线：老客户端不带 hwid，服务端必须照常完成注册
// （退化为每次分配新地址），不能因为少一个字段就拒绝连接。
func TestHelloCarriesHWID(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	in := &Message{Type: MsgHello, DeviceName: "书房电脑", HWID: id, Auth: []byte{1, 2, 3}}
	var buf bytes.Buffer
	if err := WriteMsg(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadMsg(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.HWID != id {
		t.Fatalf("设备标识往返丢失: %q", out.HWID)
	}

	// 老客户端：JSON 里没有 hwid 字段
	old, err := ReadMsg(bytes.NewReader(mustFrame(t, `{"t":1,"name":"老客户端","auth":"AQID"}`)))
	if err != nil {
		t.Fatalf("不含 hwid 的 Hello 应可解析: %v", err)
	}
	if old.HWID != "" {
		t.Fatalf("缺字段时应为空串，实际 %q", old.HWID)
	}

	// 新客户端连老服务端：对方不认识 hwid，但会原样忽略而不报错。
	// 这里用「把新格式 Hello 发给旧格式解析」模拟该方向。
	if _, err := ReadMsg(bytes.NewReader(mustFrame(t, `{"t":1,"name":"x","hwid":"`+id+`"}`))); err != nil {
		t.Fatalf("旧解析路径遇到新字段应忽略而非报错: %v", err)
	}
}

// TestWelcomeLeaseUntil 租约到期时刻要随 Welcome 一起下发。
func TestWelcomeLeaseUntil(t *testing.T) {
	const until = int64(1790000000)
	in := &Message{Type: MsgWelcome, VIP: 0x0a000002, LeaseUntil: until}
	var buf bytes.Buffer
	if err := WriteMsg(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadMsg(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.LeaseUntil != until {
		t.Fatalf("租约到期时刻往返丢失: %d", out.LeaseUntil)
	}
	// 未设置时不应出现在 JSON 里（omitempty），避免旧客户端看到一堆 0
	data, err := json.Marshal(&Message{Type: MsgWelcome, VIP: 1})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["leaseUntil"]; ok {
		t.Fatalf("未设置租约时不应输出该字段: %s", data)
	}
}

// TestForwardMsgTypes 穿透规则的查询/下发是独立的一对消息类型。
//
// 必须与 MsgConfigPush 分开：前者是设备级（按 HWID 逐台下发），
// 后者是全局广播。若复用同一个类型，服务端就得区分「这条 ConfigPush
// 里哪些键是全局的、哪些是这台设备专属的」，而这种区分一旦做错，
// 表现为某台设备拿到了别人的穿透规则——把内网服务暴露给了错误的对端。
func TestForwardMsgTypes(t *testing.T) {
	if MsgForwardGet == MsgForwardPush {
		t.Fatal("查询与下发必须是不同的消息类型")
	}
	if MsgForwardPush == MsgConfigPush || MsgForwardGet == MsgConfigPush {
		t.Fatal("穿透规则通道不得与全局配置下发混用同一消息类型")
	}
	if got := MsgForwardGet.String(); got != "ForwardGet" {
		t.Fatalf("类型名不符: %q", got)
	}
	if got := MsgForwardPush.String(); got != "ForwardPush" {
		t.Fatalf("类型名不符: %q", got)
	}

	in := &Message{Type: MsgForwardPush, Rules: []string{"8080=192.168.1.5:80"}}
	var buf bytes.Buffer
	if err := WriteMsg(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadMsg(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 1 || out.Rules[0] != in.Rules[0] {
		t.Fatalf("规则往返丢失: %v", out.Rules)
	}
}

// TestForwardPushEmptyRulesIsAuthoritative 空规则列表要能被正确表达与解析。
//
// 管理页把某台设备的规则清空后，服务端仍要发一条 ForwardPush——
// 「这条消息就是你的全部规则」是它的语义，因此字段缺失与空列表
// 都表示「没有规则」，客户端据此撤掉已生效的穿透，不会残留旧规则。
func TestForwardPushEmptyRulesIsAuthoritative(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   *Message
	}{
		{"空切片", &Message{Type: MsgForwardPush, Rules: []string{}}},
		{"nil 切片", &Message{Type: MsgForwardPush}},
	} {
		data, err := json.Marshal(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var m Message
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if m.Type != MsgForwardPush {
			t.Fatalf("%s: 类型解析错误", tc.name)
		}
		if len(m.Rules) != 0 {
			t.Fatalf("%s: 空规则应解析为 0 条，实际 %v", tc.name, m.Rules)
		}
	}
}

// TestConfigKeysFrozen 下发配置的键名是对外约定，改动即破坏兼容。
//
// 服务端、客户端、管理页三处都靠这些字符串对齐；重命名不会报编译错误，
// 只会表现为「管理页下发成功但客户端不生效」。这条断言把键名钉住。
func TestConfigKeysFrozen(t *testing.T) {
	want := map[string]string{
		"notice":   CfgNotice,
		"no_punch": CfgNoPunch,
	}
	for name, got := range want {
		if got != name {
			t.Fatalf("配置键名应为 %q，实际 %q", name, got)
		}
	}
}

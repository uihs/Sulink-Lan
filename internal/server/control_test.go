package server

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"sulink-lan/internal/protocol"
)

// startControlServer 启动测试服务器并返回实例本身（控制类测试需要调用 Push/Kick/Snapshot）。
//
// 与 server_test.go 的 startTestServer 分开：那个只返回地址，
// 是转发类测试的最小需求；控制类测试必须拿到 *Server，硬塞进旧签名会污染所有既有用例。
func startControlServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv, err := New(Config{TCPAddr: "127.0.0.1:0", UDPAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Run(ctx)
	t.Cleanup(cancel)

	deadline := time.Now().Add(3 * time.Second)
	for srv.Addr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("服务器未就绪")
		}
		time.Sleep(30 * time.Millisecond)
	}
	return srv, srv.Addr()
}

// waitDeviceCount 轮询等待在线设备数达到 want（下线/上线是异步的）。
func waitDeviceCount(t *testing.T, s *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if n := len(s.Snapshot().Devices); n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待在线设备数 %d 超时，当前 %d", want, len(s.Snapshot().Devices))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestPushDeliversToAllOnline 下发配置应送达每一台在线设备。
func TestPushDeliversToAllOnline(t *testing.T) {
	srv, addr := startControlServer(t)
	a := newFakeClient(t, addr, "push-a")
	defer a.close()
	b := newFakeClient(t, addr, "push-b")
	defer b.close()

	if n := srv.Push(map[string]string{protocol.CfgNotice: "今晚 23:00 维护"}); n != 2 {
		t.Fatalf("期望投递给 2 台设备，实际 %d", n)
	}

	for _, fc := range []*fakeClient{a, b} {
		m := fc.readMsg(t)
		if m.Type != protocol.MsgConfigPush {
			t.Fatalf("期望 ConfigPush，实际 %v", m.Type)
		}
		if got := m.Config[protocol.CfgNotice]; got != "今晚 23:00 维护" {
			t.Fatalf("公告内容不符: %q", got)
		}
	}
}

// TestPushReachesLateJoiner 下发过的配置必须对「之后才上线的设备」同样生效。
//
// 这是很容易漏掉的一环：只在 Push 的那一刻广播，新设备就永远收不到，
// 管理员得靠「记得再点一次下发」来兜底，迟早会忘。
func TestPushReachesLateJoiner(t *testing.T) {
	srv, addr := startControlServer(t)

	// 先下发，此时还没有任何设备在线
	if n := srv.Push(map[string]string{protocol.CfgNoPunch: "1"}); n != 0 {
		t.Fatalf("无设备在线时不应投递，实际 %d", n)
	}

	// 之后才上线的设备应在上线时收到
	late := newFakeClient(t, addr, "late-joiner")
	defer late.close()

	m := late.readMsg(t)
	if m.Type != protocol.MsgConfigPush {
		t.Fatalf("新上线设备未收到下发配置，实际 %v", m.Type)
	}
	if got := m.Config[protocol.CfgNoPunch]; got != "1" {
		t.Fatalf("no_punch 不符: %q", got)
	}
}

// TestPushEmptyValueClearsKey 值留空表示清除该项（否则配置只能改不能删）。
func TestPushEmptyValueClearsKey(t *testing.T) {
	srv, addr := startControlServer(t)
	a := newFakeClient(t, addr, "clear-a")
	defer a.close()

	srv.Push(map[string]string{protocol.CfgNotice: "旧公告", protocol.CfgNoPunch: "1"})
	if m := a.readMsg(t); m.Config[protocol.CfgNotice] != "旧公告" {
		t.Fatalf("首次下发未生效: %+v", m.Config)
	}

	// 清空公告，保留 no_punch
	srv.Push(map[string]string{protocol.CfgNotice: ""})
	m := a.readMsg(t)
	if _, exists := m.Config[protocol.CfgNotice]; exists {
		t.Fatalf("公告应被清除，实际仍存在: %q", m.Config[protocol.CfgNotice])
	}
	if m.Config[protocol.CfgNoPunch] != "1" {
		t.Fatal("清除公告不应影响其他配置项（合并语义被破坏）")
	}

	// 反向对照：服务端内部状态里也确实没有了
	if _, exists := srv.PushedConfig()[protocol.CfgNotice]; exists {
		t.Fatal("服务端内部状态未清除公告")
	}
}

// TestSnapshotDevices 快照应包含设备名、虚拟 IP 与 NAT 后的 UDP 地址。
func TestSnapshotDevices(t *testing.T) {
	srv, addr := startControlServer(t)
	a := newFakeClient(t, addr, "snap-a")
	defer a.close()
	waitDeviceCount(t, srv, 1)

	snap := srv.Snapshot()
	if snap.ServerVIP != "10.0.0.1" {
		t.Fatalf("服务器虚拟 IP 不符: %s", snap.ServerVIP)
	}
	if snap.VNet != protocol.VNetCIDR {
		t.Fatalf("虚拟网段不符: %s", snap.VNet)
	}
	if len(snap.Devices) != 1 {
		t.Fatalf("设备数不符: %d", len(snap.Devices))
	}
	d := snap.Devices[0]
	if d.Name != "snap-a" || d.VIP != protocol.IP4String(a.VIP) {
		t.Fatalf("设备信息不符: %+v", d)
	}
	if d.UDPAddr == "" {
		t.Fatal("UDP 地址（NAT 映射）应已记录")
	}
	if snap.TCPAddr == "" || snap.UDPAddr == "" {
		t.Fatalf("监听地址应已填充: tcp=%q udp=%q", snap.TCPAddr, snap.UDPAddr)
	}
}

// TestStatsCounters 统计计数应随转发、泛洪、伪造包而增长。
func TestStatsCounters(t *testing.T) {
	srv, addr := startControlServer(t)
	a := newFakeClient(t, addr, "stat-a")
	defer a.close()
	b := newFakeClient(t, addr, "stat-b")
	defer b.close()

	if got := srv.Snapshot().Stats; got.PktsRelayed != 0 || got.PktsFlooded != 0 {
		t.Fatalf("初始计数应为 0: %+v", got)
	}

	// 1) 普通单播：中继计数 +1
	uni, err := a.crypto.Encrypt(protocol.FlagData, a.VIP, b.VIP, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	a.sendUDP(t, addr, uni)
	waitStat(t, srv, func(s Stats) bool { return s.PktsRelayed == 1 })

	// 2) 广播：泛洪计数 +1
	bc, err := a.crypto.Encrypt(protocol.FlagData, a.VIP, protocol.VNetBroadcast, []byte("bcast"))
	if err != nil {
		t.Fatal(err)
	}
	a.sendUDP(t, addr, bc)
	waitStat(t, srv, func(s Stats) bool { return s.PktsFlooded == 1 })

	// 3) 认证失败：丢弃计数 +1
	junk := make([]byte, protocol.HeaderLen+8)
	junk[0] = protocol.FlagData
	a.sendUDP(t, addr, junk)
	waitStat(t, srv, func(s Stats) bool { return s.PktsRejected == 1 })
}

// sendUDP 通过客户端自己的 UDP socket 向服务器发一个已封装的数据包。
//
// 复用 fakeClient 的 udp 连接而不是新开一个：服务器会按来源地址刷新
// 该设备的 NAT 映射，新开 socket 会把记录改成另一个端口，干扰后续断言。
func (fc *fakeClient) sendUDP(t *testing.T, addr string, pkt []byte) {
	t.Helper()
	srvUDP, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fc.udp.WriteToUDP(pkt, srvUDP); err != nil {
		t.Fatal(err)
	}
}

// waitStat 轮询等待统计满足条件（统计在中继协程里异步累加）。
func waitStat(t *testing.T, s *Server, ok func(Stats) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if ok(s.Snapshot().Stats) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待统计条件超时，当前 %+v", s.Snapshot().Stats)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startControlServerWithFiles 启动带落盘文件的测试服务器，返回 (服务端, 地址, 配置文件路径)。
//
// 租约与全局配置都是「重启后必须还在」的东西，只测内存路径等于没测，
// 因此这类用例必须让服务端真的写文件。
func startControlServerWithFiles(t *testing.T) (*Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	leasePath := filepath.Join(dir, "devices.json")
	cfgPath := filepath.Join(dir, "server-config.json")
	srv, err := New(Config{
		TCPAddr: "127.0.0.1:0", UDPAddr: "127.0.0.1:0",
		LeaseFile: leasePath, ConfigFile: cfgPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Run(ctx)
	t.Cleanup(cancel)

	deadline := time.Now().Add(3 * time.Second)
	for srv.Addr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("服务器未就绪")
		}
		time.Sleep(30 * time.Millisecond)
	}
	return srv, srv.Addr(), cfgPath
}

// TestPushPersistsConfig 公告必须真的落到文件里。
//
// 「保存在服务器里面然后客户端连接，防止新的连接看不到」这条需求，
// 在服务端重启后仍然成立的前提就是这个文件。只改内存的话，
// 重启一次公告凭空消失，而管理员根本不知道要重发。
func TestPushPersistsConfig(t *testing.T) {
	srv, _, cfgPath := startControlServerWithFiles(t)
	srv.Push(map[string]string{protocol.CfgNotice: "今晚 23:00 维护"})

	if got := loadSettings(cfgPath); got[protocol.CfgNotice] != "今晚 23:00 维护" {
		t.Fatalf("公告未落盘: %+v", got)
	}

	// 删除公告后，文件里也必须没有这一项（而不是留一个空值）
	srv.Push(map[string]string{protocol.CfgNotice: ""})
	if got := loadSettings(cfgPath); len(got) != 0 {
		t.Fatalf("清空公告后文件里不应还有配置: %+v", got)
	}
}

// TestAddressKeptAcrossReconnect 断开重连必须拿回同一个地址——租约的核心承诺。
//
// 反向对照：把 removeDevice 的归还条件改成「下线即归还地址」，
// 这条用例立刻失败。用户看到的现象是「说好的固定地址，网络抖一下就变了」，
// 而且服务端日志里一切正常，极难排查。
func TestAddressKeptAcrossReconnect(t *testing.T) {
	srv, addr := startControlServer(t)
	a := newFakeClientHWID(t, addr, "keep-a", "hwid-keep")
	first := a.VIP
	waitDeviceCount(t, srv, 1)

	// 正常断开（不是被踢）：租约必须留着
	a.close()
	waitDeviceCount(t, srv, 0)

	b := newFakeClientHWID(t, addr, "keep-a", "hwid-keep")
	defer b.close()
	if b.VIP != first {
		t.Fatalf("断开重连应拿回同一地址 %s，实际 %s",
			protocol.IP4String(first), protocol.IP4String(b.VIP))
	}

	// 反向对照：另一台设备（不同设备标识）拿自己的地址，不与前者冲突
	c := newFakeClient(t, addr, "keep-c")
	defer c.close()
	if c.VIP == 0 || c.VIP == first {
		t.Fatalf("其他设备应拿到自己的地址，实际 %s", protocol.IP4String(c.VIP))
	}
}

// TestLeaseGrantedAndPersistedOnRegister 自动注册的设备上线即拿到租约，且立刻落盘。
func TestLeaseGrantedAndPersistedOnRegister(t *testing.T) {
	srv, addr, _ := startControlServerWithFiles(t)
	a := newFakeClientHWID(t, addr, "lease-a", "hwid-lease-a")
	defer a.close()
	waitDeviceCount(t, srv, 1)

	if a.LeaseUntil == 0 {
		t.Fatal("已注册设备应收到租约到期时刻")
	}
	want := time.Now().Add(LeaseDuration).Unix()
	if diff := a.LeaseUntil - want; diff > 60 || diff < -60 {
		t.Fatalf("租约时长不符（应约 31 天）: 到期 %d，期望约 %d", a.LeaseUntil, want)
	}

	// 反向对照：不同设备的地址互不冲突，各自有租约
	b := newFakeClient(t, addr, "lease-b")
	defer b.close()
	if b.LeaseUntil == 0 {
		t.Fatalf("其他设备同样应有租约，实际 %d", b.LeaseUntil)
	}
	if b.VIP == 0 || b.VIP == a.VIP {
		t.Fatalf("两台设备不应共用地址: %s / %s",
			protocol.IP4String(a.VIP), protocol.IP4String(b.VIP))
	}
}

// TestSetDeviceForwardPushesToOnline 管理页保存规则时，在线设备必须立刻收到。
func TestSetDeviceForwardPushesToOnline(t *testing.T) {
	srv, addr := startControlServer(t)
	a := newFakeClientHWID(t, addr, "fw-a", "hwid-fw-a")
	defer a.close()
	waitDeviceCount(t, srv, 1)

	delivered, err := srv.SetDeviceForward("hwid-fw-a", []string{"8080=192.168.1.5:80"})
	if err != nil {
		t.Fatalf("下发规则失败: %v", err)
	}
	if !delivered {
		t.Fatal("设备在线时应即时推送")
	}
	m := a.readMsg(t)
	if m.Type != protocol.MsgForwardPush {
		t.Fatalf("期望 ForwardPush，实际 %v", m.Type)
	}
	if len(m.Rules) != 1 || m.Rules[0] != "8080=192.168.1.5:80" {
		t.Fatalf("规则内容不符: %v", m.Rules)
	}

	// 非法规则必须被拒绝，且不得把已生效的规则改坏
	if _, err := srv.SetDeviceForward("hwid-fw-a", []string{"8080"}); err == nil {
		t.Fatal("非法规则应被拒绝")
	}
	if got := srv.deviceTable.Forward("hwid-fw-a"); len(got) != 1 {
		t.Fatalf("拒绝非法规则后，原有规则应保持不变: %v", got)
	}

	// 设备离线时保存成功但报告「未即时投递」，规则留在服务端等它上线
	a.close()
	waitDeviceCount(t, srv, 0)
	delivered, err = srv.SetDeviceForward("hwid-fw-a", []string{"9090=192.168.1.5:90"})
	if err != nil {
		t.Fatalf("离线设备保存规则应成功: %v", err)
	}
	if delivered {
		t.Fatal("设备离线时不应报告已投递")
	}
}

// TestForwardGetAlwaysAnswers 客户端查询规则时，服务端必须回一个**完整**答复（含「空」）。
//
// 反向对照在最后一段：没有规则的设备也必须收到一条空推送，
// 而不是「什么都不回」——客户端据此才能确认「确实没有规则」，
// 否则它会一直保留上一次的规则，管理页删掉的规则在设备上永远残留。
func TestForwardGetAlwaysAnswers(t *testing.T) {
	srv, addr := startControlServer(t)
	if _, err := srv.SetDeviceForward("hwid-q", []string{"8080=192.168.1.5:80"}); err != nil {
		t.Fatal(err)
	}
	a := newFakeClientHWID(t, addr, "q-a", "hwid-q")
	defer a.close()

	if err := protocol.WriteMsg(a.tcp, &protocol.Message{Type: protocol.MsgForwardGet}); err != nil {
		t.Fatal(err)
	}
	m := a.readMsg(t)
	if m.Type != protocol.MsgForwardPush || len(m.Rules) != 1 {
		t.Fatalf("查询应答不符: %+v", m)
	}

	b := newFakeClientHWID(t, addr, "q-b", "hwid-q2")
	defer b.close()
	if err := protocol.WriteMsg(b.tcp, &protocol.Message{Type: protocol.MsgForwardGet}); err != nil {
		t.Fatal(err)
	}
	m2 := b.readMsg(t)
	if m2.Type != protocol.MsgForwardPush {
		t.Fatalf("无规则的设备也应收到推送，实际 %v", m2.Type)
	}
	if len(m2.Rules) != 0 {
		t.Fatalf("无规则设备的规则应为空: %v", m2.Rules)
	}
}

// TestSetDeviceIPDisconnectsAndTakesEffectOnReconnect 改地址的完整生效链路。
//
// 虚拟网卡地址无法热改（TUN 层各平台都要重建网卡），因此实现为
// 「改租约 + 断开在线连接」，由客户端自动重连后启用新地址。
// 这个用例把整条链路走一遍：断开 -> 用同一设备标识重连 -> 拿到新地址。
func TestSetDeviceIPDisconnectsAndTakesEffectOnReconnect(t *testing.T) {
	srv, addr := startControlServer(t)
	a := newFakeClientHWID(t, addr, "ip-a", "hwid-ip-a")
	defer a.close()
	waitDeviceCount(t, srv, 1)

	reconnect, err := srv.SetDeviceIP("hwid-ip-a", "10.0.0.9")
	if err != nil {
		t.Fatalf("改地址失败: %v", err)
	}
	if !reconnect {
		t.Fatal("设备在线时应断开连接以触发重连")
	}
	waitDeviceCount(t, srv, 0) // 连接已被服务端关闭
	// 同一个设备标识重新上线，应拿到新地址
	a2 := newFakeClientHWID(t, addr, "ip-a", "hwid-ip-a")
	defer a2.close()
	if got := protocol.IP4String(a2.VIP); got != "10.0.0.9" {
		t.Fatalf("重连后应使用新地址 10.0.0.9，实际 %s", got)
	}

	// 反向对照一：已被占用的地址不能改给别人
	b := newFakeClientHWID(t, addr, "ip-b", "hwid-ip-b")
	defer b.close()
	if _, err := srv.SetDeviceIP("hwid-ip-b", "10.0.0.9"); err == nil {
		t.Fatal("把已占用的地址分配给另一台设备应报错")
	}
	// 反向对照二：不存在的设备、越界地址都要报错，而不是静默成功
	if _, err := srv.SetDeviceIP("hwid-nope", "10.0.0.9"); err == nil {
		t.Fatal("对不存在的设备改地址应报错")
	}
	if _, err := srv.SetDeviceIP("hwid-ip-b", "10.0.0.1"); err == nil {
		t.Fatal("服务器自身地址不可分配")
	}
	if _, err := srv.SetDeviceIP("hwid-ip-b", "not-an-ip"); err == nil {
		t.Fatal("非法地址格式应报错")
	}
	// b 未被任何失败调用改动，仍在原地址
	if got := protocol.IP4String(b.VIP); got == "10.0.0.9" {
		t.Fatalf("失败的改地址调用不应生效，b 实际 %s", got)
	}
}

// TestSnapshotIncludesLeases 快照必须带上租约表（管理页改地址、配规则全靠它）。
func TestSnapshotIncludesLeases(t *testing.T) {
	srv, addr := startControlServer(t)
	a := newFakeClientHWID(t, addr, "snap-lease", "hwid-snap")
	defer a.close()
	waitDeviceCount(t, srv, 1)
	if _, err := srv.SetDeviceForward("hwid-snap", []string{"8080=192.168.1.5:80"}); err != nil {
		t.Fatal(err)
	}

	snap := srv.Snapshot()
	if snap.LeaseDays != 31 {
		t.Fatalf("租约天数应返回 31，实际 %d", snap.LeaseDays)
	}
	if len(snap.Leases) != 1 {
		t.Fatalf("应有 1 条租约，实际 %d", len(snap.Leases))
	}
	li := snap.Leases[0]
	if li.HWID != "hwid-snap" || li.Name != "snap-lease" {
		t.Fatalf("租约归属不符: %+v", li)
	}
	if !li.Online || li.VIP != protocol.IP4String(a.VIP) {
		t.Fatalf("在线状态或地址不符: %+v", li)
	}
	if li.RemainSecs <= 0 || len(li.Forward) != 1 {
		t.Fatalf("租约剩余时间或穿透规则不符: %+v", li)
	}
}

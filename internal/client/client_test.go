package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"sulink-lan/internal/protocol"
	"sulink-lan/internal/server"
)

// mockTun 内存模拟虚拟网卡：
//
//	in: 注入"内核路由到 TUN"的包（tunLoop 读出）
//	out: 收集"写入 TUN 进入内核"的包（测试断言）
type mockTun struct {
	name string
	in   chan []byte
	out  chan []byte
	once sync.Once
	// 记录 Configure 收到的参数（用于断言配置正确性）
	cfgIP string
}

func newMockTun(name string) *mockTun {
	return &mockTun{name: name, in: make(chan []byte, 512), out: make(chan []byte, 512)}
}

func (m *mockTun) Read(buf []byte) (int, error) {
	pkt, ok := <-m.in
	if !ok {
		return 0, io.EOF
	}
	return copy(buf, pkt), nil
}

func (m *mockTun) Write(buf []byte) (int, error) {
	pkt := make([]byte, len(buf))
	copy(pkt, buf)
	m.out <- pkt
	return len(pkt), nil
}

// Configure 记录被配置的参数，便于断言网卡按虚拟 IP 正确配置。
func (m *mockTun) Configure(ip string) error {
	m.cfgIP = ip
	return nil
}
func (m *mockTun) Close() error {
	m.once.Do(func() { close(m.in) })
	return nil
}
func (m *mockTun) Name() string { return m.name }

// setup 启动一个服务器 + 两个真实客户端（各挂一块内存网卡）。
// aNoPunch/bNoPunch 控制双方是否禁用打洞（测试中继路径时双方都禁用，
// 避免本地回环环境下打洞总是"成功"而混入 P2P 流量）。
func setup(t *testing.T, aForwards []ForwardRule, aNoPunch, bNoPunch bool) (addr string, ta, tb *mockTun, ca, cb *Client) {
	t.Helper()
	_, addr, ta, tb, ca, cb = setupFull(t, aForwards, aNoPunch, bNoPunch)
	return addr, ta, tb, ca, cb
}

// setupFull 与 setup 相同，但额外返回服务端句柄，
// 供需要「运行中改服务端配置」的用例使用（例如即时下发穿透规则）。
func setupFull(t *testing.T, aForwards []ForwardRule, aNoPunch, bNoPunch bool) (srv *server.Server, addr string, ta, tb *mockTun, ca, cb *Client) {
	t.Helper()
	// 端口填 0：服务器随机分配，通过 Addr() 获取实际地址（消除 TOCTOU 竞态）
	srv, err := server.New(server.Config{TCPAddr: "127.0.0.1:0", UDPAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Run(ctx)
	t.Cleanup(cancel)

	// 等待服务器真正开始监听
	deadline := time.Now().Add(3 * time.Second)
	for {
		addr = srv.Addr()
		if addr != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("服务器未就绪")
		}
		time.Sleep(30 * time.Millisecond)
	}

	ta = newMockTun("ta")
	tb = newMockTun("tb")

	// 两个客户端必须使用**不同**的设备标识。留空的话它们会各自算出同一个
	// 本机标识（同一台测试机），于是争抢同一个 IP 租约，服务端按
	// 「新连接接管旧连接」把先连上的那个踢掉——测试会以极难排查的方式失败。
	const hwidA, hwidB = "test-hwid-alice", "test-hwid-bob"

	// 穿透规则先存进服务端，再让客户端连接：客户端已经没有本地规则入口，
	// 只能靠连接时主动查询取回。这个顺序也正对应管理页的实际用法——
	// 管理员先规划好规则，设备再上线。
	if len(aForwards) > 0 {
		lines := make([]string, 0, len(aForwards))
		for _, r := range aForwards {
			lines = append(lines, r.String())
		}
		if _, err := srv.SetDeviceForward(hwidA, lines); err != nil {
			t.Fatalf("预置穿透规则失败: %v", err)
		}
	}

	ca = NewClient(Config{Server: addr, Name: "ca", HWID: hwidA, NoPunch: aNoPunch})
	cb = NewClient(Config{Server: addr, Name: "cb", HWID: hwidB, NoPunch: bNoPunch})
	ca.newTun = func() (Tun, error) { return ta, nil }
	cb.newTun = func() (Tun, error) { return tb, nil }
	go ca.Run()
	go cb.Run()
	t.Cleanup(ca.Close)
	t.Cleanup(cb.Close)
	waitVIP(t, ca)
	waitVIP(t, cb)
	waitReady(t, ca)
	waitReady(t, cb)
	// 规则是连接建立后异步到达的（客户端发查询、信令循环收答复），
	// ready 只表示会话就绪，所以必须单独等一次。
	if len(aForwards) > 0 {
		waitRules(t, ca, len(aForwards))
	}
	return srv, addr, ta, tb, ca, cb
}

// TestLeaseUntilFromServer 租约到期时刻必须如实取自服务端 Welcome。
//
// 这个值会显示成界面上的「地址保留至 X」。曾经它没有被保存下来，
// 界面上永远是空——用户因此无法判断地址到底是「被保留的」还是「碰巧分到的」，
// 也就无法信任「固定地址」这个承诺。
func TestLeaseUntilFromServer(t *testing.T) {
	_, _, _, _, ca, _ := setupFull(t, nil, true, true)
	got := ca.LeaseUntil()
	if got <= 0 {
		t.Fatalf("带设备标识的客户端应拿到租约到期时刻，实际 %d", got)
	}
	want := time.Now().Add(server.LeaseDuration).Unix()
	if diff := got - want; diff > 120 || diff < -120 {
		t.Fatalf("租约时长不符（应约 %d 天）: 实际到期 %d，期望约 %d",
			int(server.LeaseDuration.Hours()/24), got, want)
	}
}

// waitRules 等待客户端收到指定条数的穿透规则。
//
// 不等的话，测试会在规则尚未生效时发包，失败现象看起来像「NAT 坏了」，
// 而真正的原因只是慢了几毫秒。
func waitRules(t *testing.T, c *Client, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(c.Rules()) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("客户端未收到 %d 条穿透规则，实际 %d 条", want, len(c.Rules()))
}

// waitReady 等待客户端会话完全就绪（注册、网卡、数据循环全部启动）。
func waitReady(t *testing.T, c *Client) {
	t.Helper()
	select {
	case <-c.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("客户端会话未就绪")
	}
}

func waitVIP(t *testing.T, c *Client) uint32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v := c.self.Load(); v != 0 {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("客户端未获得虚拟 IP")
	return 0
}

func waitP2P(t *testing.T, c *Client, vip uint32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.isP2P(vip) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("客户端与 %s 未建立 P2P", protocol.IP4String(vip))
}

func waitOut(t *testing.T, m *mockTun) []byte {
	t.Helper()
	select {
	case pkt := <-m.out:
		return pkt
	case <-time.After(5 * time.Second):
		t.Fatal("等待 TUN 出包超时")
		return nil
	}
}

// ---- 构造 IP 包 ----

func icmpEcho(src, dst uint32, id, seq uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	binary.BigEndian.PutUint32(pkt[12:16], src)
	binary.BigEndian.PutUint32(pkt[16:20], dst)
	// ICMP 头：type(20) code(21) checksum(22:24) id(24:26) seq(26:28)。
	// id/seq 必须落在 24:26 / 26:28 —— 22:24 是校验和字段，
	// 早期版本误把 id 写在这里，随后又被校验和覆盖，导致 id 根本无法回显。
	pkt[20] = 8 // echo request
	pkt[21] = 0
	binary.BigEndian.PutUint16(pkt[22:24], 0)
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	binary.BigEndian.PutUint16(pkt[22:24], checksum(pkt[20:]))
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	return pkt
}

func tcpPacket(srcIP, dstIP uint32, srcPort, dstPort uint16, flags uint8, seq uint32) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	binary.BigEndian.PutUint32(pkt[12:16], srcIP)
	binary.BigEndian.PutUint32(pkt[16:20], dstIP)
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 0x50
	tcp[13] = flags
	pseudo := make([]byte, 12+len(tcp))
	binary.BigEndian.PutUint32(pseudo[0:4], srcIP)
	binary.BigEndian.PutUint32(pseudo[4:8], dstIP)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	sum := checksum(pseudo)
	binary.BigEndian.PutUint16(tcp[16:18], sum)
	ipSum := checksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipSum)
	return pkt
}

// udpPacket 构造一个带完整 IPv4 头与伪头部校验和的 UDP 报文。
// 局域网发现类协议走 UDP，用它才能覆盖「改写地址后校验和仍有效」这条路径。
func udpPacket(srcIP, dstIP uint32, srcPort, dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	pkt := make([]byte, 20+len(udp))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	binary.BigEndian.PutUint32(pkt[12:16], srcIP)
	binary.BigEndian.PutUint32(pkt[16:20], dstIP)
	copy(pkt[20:], udp)

	pseudo := make([]byte, 12+len(udp))
	binary.BigEndian.PutUint32(pseudo[0:4], srcIP)
	binary.BigEndian.PutUint32(pseudo[4:8], dstIP)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	binary.BigEndian.PutUint16(pkt[26:28], checksum(pseudo))
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	return pkt
}

// verifyChecksums 校验 IP 头与 TCP 校验和（NAT 改写后必须仍然有效）。
func verifyChecksums(t *testing.T, pkt []byte) {
	t.Helper()
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		t.Fatal("不是 IPv4 包")
	}
	ihl := int(pkt[0]&0x0f) * 4
	// 头校验和：清零后重算
	saved := binary.BigEndian.Uint16(pkt[10:12])
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	if checksum(pkt[:ihl]) != saved {
		t.Fatalf("IP 头校验和不正确")
	}
	binary.BigEndian.PutUint16(pkt[10:12], saved)
	if pkt[9] != 6 && pkt[9] != 17 {
		return
	}
	seg := pkt[ihl:]
	csumOff := 16
	if pkt[9] == 17 {
		csumOff = 6
	}
	if len(seg) < csumOff+2 {
		return
	}
	sv := binary.BigEndian.Uint16(seg[csumOff : csumOff+2])
	binary.BigEndian.PutUint16(seg[csumOff:csumOff+2], 0)
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = pkt[9]
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	if checksum(pseudo) != sv {
		t.Fatalf("TCP/UDP 校验和不正确")
	}
	binary.BigEndian.PutUint16(seg[csumOff:csumOff+2], sv)
}

// TestP2PForwardAndPunch 验证：注册、P2P 打洞、三层 ICMP 转发。
func TestP2PForwardAndPunch(t *testing.T) {
	_, ta, tb, ca, cb := setup(t, nil, false, false)
	aVIP, bVIP := ca.self.Load(), cb.self.Load()
	if aVIP == bVIP {
		t.Fatal("虚拟 IP 冲突")
	}
	waitP2P(t, ca, bVIP)
	waitP2P(t, cb, aVIP)

	// bob 侧注入发往 alice 的 ICMP echo（模拟 bob 内核发出）
	req := icmpEcho(bVIP, aVIP, 1, 1)
	tb.in <- req
	got := waitOut(t, ta)
	if string(got) != string(req) {
		t.Fatalf("P2P 转发内容不一致")
	}

	// alice 回复 echo reply
	rep := icmpEcho(aVIP, bVIP, 1, 1)
	rep[20] = 0 // reply
	icmpSum := checksum(rep[20:])
	binary.BigEndian.PutUint16(rep[22:24], icmpSum)
	ta.in <- rep
	got2 := waitOut(t, tb)
	if string(got2) != string(rep) {
		t.Fatalf("P2P 回包内容不一致")
	}
}

// TestRelayPath 验证：禁用打洞的双方走服务器中转，数据仍可达；
// 同时回归验证 P0-2 修复——经服务器中继的数据不得被误判为 P2P 直连。
func TestRelayPath(t *testing.T) {
	_, ta, tb, ca, cb := setup(t, nil, true, true) // 双方强制中继
	aVIP, bVIP := ca.self.Load(), cb.self.Load()

	// bob（强制中转）发 ICMP 给 alice
	req := icmpEcho(bVIP, aVIP, 2, 2)
	tb.in <- req
	got := waitOut(t, ta)
	if string(got) != string(req) {
		t.Fatalf("中继转发内容不一致")
	}

	// 回归：数据虽经中继到达，双方均不得标记为 P2P（旧实现会误报"直连成功"）
	if ca.isP2P(bVIP) {
		t.Fatalf("BUG 回归：中继流量被误判为 P2P 直连（ca）")
	}
	if cb.isP2P(aVIP) {
		t.Fatalf("BUG 回归：中继流量被误判为 P2P 直连（cb）")
	}

	// alice 回包也应通过中继到达 bob
	rep := icmpEcho(aVIP, bVIP, 2, 2)
	rep[20] = 0
	icmpSum := checksum(rep[20:])
	binary.BigEndian.PutUint16(rep[22:24], icmpSum)
	ta.in <- rep
	got2 := waitOut(t, tb)
	if string(got2) != string(rep) {
		t.Fatalf("中继回包内容不一致")
	}
	if ca.isP2P(bVIP) || cb.isP2P(aVIP) {
		t.Fatalf("BUG 回归：中继回包被误判为 P2P")
	}
}

// TestPingServerVIPThroughClient 回归验证用户端的完整路径：
//
//	ping 10.0.0.1 → 内核按 10.0.0.0/8 路由交给 TUN → tunLoop 加密发出
//	→ 服务端合成 ICMP 应答 → udpLoop 解密 → 写回 TUN → ping 收到 echo reply
//
// 用户端无需任何改动：服务端应答的是一条普通 FlagData 包，客户端按既有
// 逻辑处理即可。本测试锁住这条路径，防止日后「顺手优化」时被打断。
func TestPingServerVIPThroughClient(t *testing.T) {
	// 双方强制中继：ping 网关必定经服务端，不掺入 P2P 流量
	_, ta, _, ca, _ := setup(t, nil, true, true)
	aVIP := ca.self.Load()

	srvVIP, err := protocol.IP4("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if aVIP == srvVIP {
		t.Fatalf("客户端不应被分配到服务器 VIP %s", protocol.IP4String(srvVIP))
	}

	// 模拟内核把 ping 10.0.0.1 的 echo request 路由到虚拟网卡
	req := icmpEcho(aVIP, srvVIP, 0x7788, 3)
	ta.in <- req

	got := waitOut(t, ta)
	if len(got) < 28 {
		t.Fatalf("应答长度异常: %d", len(got))
	}
	if got[9] != 1 {
		t.Fatalf("写回 TUN 的不是 ICMP 包（proto=%d）", got[9])
	}
	if got[20] != 0 {
		t.Fatalf("ICMP 类型应为 echo reply(0)，实际 %d", got[20])
	}
	// 应答的源必须是服务器 VIP、目的必须是本机 VIP
	if s := binary.BigEndian.Uint32(got[12:16]); s != srvVIP {
		t.Fatalf("应答源地址应为 %s，实际 %s", protocol.IP4String(srvVIP), protocol.IP4String(s))
	}
	if d := binary.BigEndian.Uint32(got[16:20]); d != aVIP {
		t.Fatalf("应答目的地址应为 %s，实际 %s", protocol.IP4String(aVIP), protocol.IP4String(d))
	}
	// id/seq 必须原样带回，否则系统 ping 会认为应答不属于本次请求
	if id := binary.BigEndian.Uint16(got[24:26]); id != 0x7788 {
		t.Fatalf("应答未回显 ping 的 id：期望 0x7788，实际 0x%04x", id)
	}
	if seq := binary.BigEndian.Uint16(got[26:28]); seq != 3 {
		t.Fatalf("应答未回显 ping 的 seq：期望 3，实际 %d", seq)
	}
	// 校验和必须有效（整段反码求和为 0）
	if checksum(got[:20]) != 0 {
		t.Fatal("应答 IP 头校验和不正确")
	}
	if checksum(got[20:]) != 0 {
		t.Fatal("应答 ICMP 校验和不正确")
	}
	// 服务器 VIP 不是 P2P 对端，不得被标记为「直连」
	if ca.isP2P(srvVIP) {
		t.Fatal("服务器 VIP 被误标为 P2P 直连对端")
	}
}

// TestBroadcastFloodThroughClient 回归验证网段定向广播的端到端交付：
//
//	b 上的应用向 10.255.255.255 发包（局域网发现类协议正是这么做的）
//	→ 经隧道到服务端 → 泛洪给 a → a 交付给本机内核
//
// 交付前必须把目标地址改写成本机虚拟 IP：虚拟网卡是 /32，接口不「拥有」
// 任何网段、也就没有主机位，内核不会认 10.255.255.255 是本接口的广播地址，
// 原样写回 TUN 会被内核直接丢掉——包已经送到进程里了，却在最后一步消失。
func TestBroadcastFloodThroughClient(t *testing.T) {
	_, ta, tb, ca, cb := setup(t, nil, true, true)
	aVIP, bVIP := ca.self.Load(), cb.self.Load()

	payload := []byte("lan-discovery-payload")
	req := udpPacket(bVIP, protocol.VNetBroadcast, 40000, 19132, payload)
	tb.in <- req

	got := waitOut(t, ta)
	if len(got) != len(req) {
		t.Fatalf("交付到 TUN 的包长度异常: 期望 %d，实际 %d", len(req), len(got))
	}
	if got[9] != 17 {
		t.Fatalf("协议字段被破坏: %d", got[9])
	}
	if d := binary.BigEndian.Uint32(got[16:20]); d != aVIP {
		t.Fatalf("广播目标应改写为本机虚拟 IP %s，实际 %s",
			protocol.IP4String(aVIP), protocol.IP4String(d))
	}
	if s := binary.BigEndian.Uint32(got[12:16]); s != bVIP {
		t.Fatalf("广播源地址应保持为 %s，实际 %s",
			protocol.IP4String(bVIP), protocol.IP4String(s))
	}
	// 端口与载荷必须原样保留：发现协议靠载荷里的地址端口信息回连
	if p := binary.BigEndian.Uint16(got[22:24]); p != 19132 {
		t.Fatalf("目标端口应保留 19132，实际 %d", p)
	}
	if string(got[28:]) != string(payload) {
		t.Fatalf("载荷被改动: %q", got[28:])
	}
	verifyChecksums(t, got) // 改写地址后两级校验和必须仍然有效

	// 对照：发送者本人不应收到自己广播的回环
	select {
	case p := <-tb.out:
		t.Fatalf("发送者收到了自己广播的回环: %d 字节", len(p))
	case <-time.After(600 * time.Millisecond):
	}
}

// TestForwardRulesOnlyFromServer 验证穿透规则只能来自服务端，且运行中改动即时生效。
//
// 这是「客户端无法自行添加穿透规则，必须由服务端下发」这条约束的回归用例：
//   - 客户端启动时不带任何规则（配置里根本没有这个字段）；
//   - 管理页保存规则 → 在线设备立即生效；
//   - 清空规则 → 立即停止穿透（整体替换，而不是只增不减）。
//
// 反向对照就在最后一段：若哪天有人把规则改成「合并」语义，
// 「清空后仍在 DNAT」这一步会立刻失败。
func TestForwardRulesOnlyFromServer(t *testing.T) {
	srv, _, ta, tb, ca, cb := setupFull(t, nil, true, true) // 双方中继即可，NAT 与路径无关
	aVIP, bVIP := ca.self.Load(), cb.self.Load()

	if n := len(ca.Rules()); n != 0 {
		t.Fatalf("客户端启动时不应带任何穿透规则，实际 %d 条", n)
	}

	targetIP, _ := ip4u32("127.0.0.1")
	delivered, err := srv.SetDeviceForward(ca.cfg.HWID, []string{"8000=127.0.0.1:8000"})
	if err != nil {
		t.Fatalf("下发规则失败: %v", err)
	}
	if !delivered {
		t.Fatal("设备在线时应即时下发，实际报告为未投递")
	}
	waitRules(t, ca, 1)

	// 规则已生效：bob 访问 alice 的虚拟 8000 端口应被 DNAT 到 127.0.0.1:8000
	tb.in <- tcpPacket(bVIP, aVIP, 40000, 8000, 0x02, 100)
	got := waitOut(t, ta)
	if ip := binary.BigEndian.Uint32(got[16:20]); ip != targetIP {
		t.Fatalf("运行中下发的规则未生效，DNAT 目标 = %s", protocol.IP4String(ip))
	}

	// 清空规则：整体替换语义下必须立刻停止穿透
	if _, err := srv.SetDeviceForward(ca.cfg.HWID, nil); err != nil {
		t.Fatalf("清空规则失败: %v", err)
	}
	waitRules(t, ca, 0)

	tb.in <- tcpPacket(bVIP, aVIP, 40001, 8000, 0x02, 101)
	got2 := waitOut(t, ta)
	if ip := binary.BigEndian.Uint32(got2[16:20]); ip != aVIP {
		t.Fatalf("规则清空后仍在 DNAT（规则被合并而非替换？）：目标 = %s", protocol.IP4String(ip))
	}
}

// TestNatForward 验证：内网穿透 DNAT 与回包 SNAT（校验和保持有效）。
func TestNatForward(t *testing.T) {
	targetIP, _ := ip4u32("127.0.0.1")
	rules := []ForwardRule{{VPort: 8000, TargetIP: targetIP, TargetPort: 8000}}
	_, ta, tb, ca, cb := setup(t, rules, false, false)
	aVIP, bVIP := ca.self.Load(), cb.self.Load()
	waitP2P(t, ca, bVIP)

	// bob 发起 TCP SYN 访问 alice 虚拟端口 8000
	syn := tcpPacket(bVIP, aVIP, 40000, 8000, 0x02, 100)
	tb.in <- syn

	// alice 侧收到 DNAT 后的包：目标变为 127.0.0.1:8000
	got := waitOut(t, ta)
	if len(got) < 40 {
		t.Fatalf("DNAT 包长度异常")
	}
	dstIP := binary.BigEndian.Uint32(got[16:20])
	if dstIP != targetIP {
		t.Fatalf("DNAT 目标 IP 错误: %s", protocol.IP4String(dstIP))
	}
	dstPort := binary.BigEndian.Uint16(got[22:24])
	if dstPort != 8000 {
		t.Fatalf("DNAT 目标端口错误: %d", dstPort)
	}
	verifyChecksums(t, got)

	// 内网服务回 SYN-ACK（源 127.0.0.1:8000），alice 路由到 TUN，SNAT 后发给 bob
	synack := tcpPacket(targetIP, bVIP, 8000, 40000, 0x12, 500)
	ta.in <- synack
	got2 := waitOut(t, tb)
	if len(got2) < 40 {
		t.Fatalf("SNAT 包长度异常")
	}
	srcIP := binary.BigEndian.Uint32(got2[12:16])
	if srcIP != aVIP {
		t.Fatalf("SNAT 源 IP 错误: %s", protocol.IP4String(srcIP))
	}
	srcPort := binary.BigEndian.Uint16(got2[20:22])
	if srcPort != 8000 {
		t.Fatalf("SNAT 源端口错误: %d", srcPort)
	}
	verifyChecksums(t, got2)
}

// TestNatPortRewrite 回归验证 P0-1 修复：虚拟端口 != 目标端口时
// （管理页里的规则示例 8445=192.168.1.50:445），DNAT 必须同时改写 IP 与端口，
// SNAT 回包把源端口改回虚拟端口。旧实现漏掉端口改写，导致此类规则完全不工作。
func TestNatPortRewrite(t *testing.T) {
	targetIP, _ := ip4u32("192.168.1.50")
	rules := []ForwardRule{{VPort: 8445, TargetIP: targetIP, TargetPort: 445}}
	_, ta, tb, ca, cb := setup(t, rules, true, true) // 双方中继即可，NAT 与路径无关
	aVIP, bVIP := ca.self.Load(), cb.self.Load()

	// bob 发 SYN 到 alice 虚拟端口 8445
	syn := tcpPacket(bVIP, aVIP, 50000, 8445, 0x02, 100)
	tb.in <- syn

	// alice 侧收到 DNAT 后的包：目标必须变为 192.168.1.50:445（IP 与端口都改写）
	got := waitOut(t, ta)
	if len(got) < 40 {
		t.Fatalf("DNAT 包长度异常")
	}
	if ip := binary.BigEndian.Uint32(got[16:20]); ip != targetIP {
		t.Fatalf("DNAT 目标 IP 错误: %s", protocol.IP4String(ip))
	}
	if port := binary.BigEndian.Uint16(got[22:24]); port != 445 {
		t.Fatalf("BUG 回归：DNAT 未改写目标端口，期望 445，实际 %d", port)
	}
	verifyChecksums(t, got)

	// 内网服务（192.168.1.50:445）回 SYN-ACK，SNAT 后源地址还原为 alice:8445
	synack := tcpPacket(targetIP, bVIP, 445, 50000, 0x12, 500)
	ta.in <- synack
	got2 := waitOut(t, tb)
	if len(got2) < 40 {
		t.Fatalf("SNAT 包长度异常")
	}
	if ip := binary.BigEndian.Uint32(got2[12:16]); ip != aVIP {
		t.Fatalf("SNAT 源 IP 错误: %s", protocol.IP4String(ip))
	}
	if port := binary.BigEndian.Uint16(got2[20:22]); port != 8445 {
		t.Fatalf("SNAT 源端口错误: 期望 8445，实际 %d", port)
	}
	verifyChecksums(t, got2)
}

// TestNatUDPRewrite 回归验证：UDP 包经 DNAT/SNAT 改写地址后校验和必须重算。
//
// 旧实现把「UDP 校验和为 0 表示不校验」错写成 seg[6]&0x01 == 0
// （只看校验和高字节的最低位），约一半的 UDP 包会被误判为「不校验」
// 而跳过重算：地址改了、校验和没改，收端一律丢弃，
// 表现为「UDP 穿透时通时不通」。此前 NAT 测试只用 TCP，这条路径没有覆盖。
func TestNatUDPRewrite(t *testing.T) {
	targetIP, _ := ip4u32("192.168.1.60")
	rules := []ForwardRule{{VPort: 19132, TargetIP: targetIP, TargetPort: 19133}}
	_, ta, tb, ca, cb := setup(t, rules, true, true) // 中继即可，NAT 与路径无关
	aVIP, bVIP := ca.self.Load(), cb.self.Load()

	// bob 向 alice 虚拟端口 19132 发 UDP
	req := udpPacket(bVIP, aVIP, 50000, 19132, []byte("discovery-ping"))
	tb.in <- req

	got := waitOut(t, ta)
	if len(got) != len(req) {
		t.Fatalf("DNAT 包长度异常: 期望 %d，实际 %d", len(req), len(got))
	}
	if ip := binary.BigEndian.Uint32(got[16:20]); ip != targetIP {
		t.Fatalf("DNAT 目标 IP 错误: %s", protocol.IP4String(ip))
	}
	if port := binary.BigEndian.Uint16(got[22:24]); port != 19133 {
		t.Fatalf("DNAT 目标端口错误: 期望 19133，实际 %d", port)
	}
	verifyChecksums(t, got) // 关键：改写后 UDP 校验和必须仍然有效

	// 内网服务（192.168.1.60:19133）回包 → SNAT 还原为 alice:19132
	rep := udpPacket(targetIP, bVIP, 19133, 50000, []byte("discovery-pong"))
	ta.in <- rep

	got2 := waitOut(t, tb)
	if len(got2) != len(rep) {
		t.Fatalf("SNAT 包长度异常: 期望 %d，实际 %d", len(rep), len(got2))
	}
	if ip := binary.BigEndian.Uint32(got2[12:16]); ip != aVIP {
		t.Fatalf("SNAT 源 IP 错误: %s", protocol.IP4String(ip))
	}
	if port := binary.BigEndian.Uint16(got2[20:22]); port != 19132 {
		t.Fatalf("SNAT 源端口错误: 期望 19132，实际 %d", port)
	}
	verifyChecksums(t, got2)
}

// waitGoroutineDrop 轮询等待 goroutine 数回落到 base 以下（超时视为泄漏）。
// 用轮询而非固定 sleep + 绝对值比较，避免前序测试残留协程退出时序造成的 flaky。
func waitGoroutineDrop(t *testing.T, base int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutine 未回落（疑似泄漏）：%d -> %d", base, runtime.NumGoroutine())
}

// TestHeartbeatLoopExits 回归验证 P1-3 修复：
// 会话结束（session 关闭）后 heartbeatLoop 必须退出，不得随重连累积泄漏。
func TestHeartbeatLoopExits(t *testing.T) {
	c := NewClient(Config{Server: "127.0.0.1:1", Name: "t"})
	c.session = make(chan struct{})
	p1, p2 := net.Pipe()
	defer p2.Close()
	c.conn = p1

	base := runtime.NumGoroutine()
	go c.heartbeatLoop()
	time.Sleep(150 * time.Millisecond) // 确保协程已启动
	close(c.session)                   // 结束会话
	waitGoroutineDrop(t, base, 2*time.Second)
}

// TestNatCleanLoopExits 回归验证 P1-4 修复：
// Nat.Close 后 cleanLoop 必须退出；客户端重连会重建 Nat，旧实例不关闭则持续泄漏。
func TestNatCleanLoopExits(t *testing.T) {
	base := runtime.NumGoroutine()
	n := NewNat(1, nil)
	time.Sleep(150 * time.Millisecond) // 确保协程已启动
	n.Close()
	waitGoroutineDrop(t, base, 2*time.Second)
	// 幂等性：重复 Close 不得 panic
	n.Close()
}

// TestNatMalformedPacketsNoPanic 回归验证：畸形 IP 包不得让 NAT 越界 panic。
//
// 早期实现中，IP 头 total 字段被写成「只比头长多 4~6 字节」（如 total=24、ihl=20，
// 声称是 UDP 但传输层头都没到齐）的包，会在 rewriteChecksums 访问 seg[6]/seg[7]
// 时越界 panic，把整个客户端进程打崩。攻击者只需向穿透端口发一个此类包即可触发，
// 属可远程利用的 DoS。本用例确认 DNAT/SNAT 对这类包安全返回 false 而非崩溃。
func TestNatMalformedPacketsNoPanic(t *testing.T) {
	targetIP, _ := ip4u32("192.168.1.60")
	n := NewNat(0x0A000002, []ForwardRule{{VPort: 8080, TargetIP: targetIP, TargetPort: 80}})
	defer n.Close()

	// 1) total(24) 比 ihl(20) 只多 4 字节、声称 UDP 的畸形包（旧实现越界点）
	short := make([]byte, 24)
	short[0] = 0x45
	binary.BigEndian.PutUint16(short[2:4], 24)
	short[8], short[9] = 64, 17 // TTL, UDP
	binary.BigEndian.PutUint32(short[12:16], 0x0A0000FF)
	binary.BigEndian.PutUint32(short[16:20], 0x0A000002)
	binary.BigEndian.PutUint16(short[20:22], 12345)
	binary.BigEndian.PutUint16(short[22:24], 8080) // 命中规则
	if n.DNAT(short) {
		t.Fatal("畸形 UDP 包不应命中 DNAT 并被改写")
	}

	// 2) total 字段小于头长度（total=10, ihl=20）的包（旧实现切片负长度风险点）
	neg := make([]byte, 40)
	neg[0] = 0x45
	binary.BigEndian.PutUint16(neg[2:4], 10)
	neg[8], neg[9] = 64, 6 // TCP
	binary.BigEndian.PutUint32(neg[12:16], 0x0A0000FF)
	binary.BigEndian.PutUint32(neg[16:20], 0x0A000002)
	if n.DNAT(neg) {
		t.Fatal("负长度包不应命中 DNAT")
	}

	// 3) 合法 UDP 包必须仍能正常命中（防回归：防护过严把正常包也拦掉）
	ok := udpPacket(0x0A0000FF, 0x0A000002, 50000, 8080, []byte("ok"))
	if !n.DNAT(ok) {
		t.Fatal("合法 UDP 包应命中 DNAT")
	}
	verifyChecksums(t, ok)
}

// ===== 自动注册（按设备标识 HWID）端到端 =====

// startAuthServer 启动测试服务器，返回句柄与地址。
func startAuthServer(t *testing.T) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(server.Config{TCPAddr: "127.0.0.1:0", UDPAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Run(ctx)
	t.Cleanup(cancel)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if addr := srv.Addr(); addr != "" {
			return srv, addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("服务器未就绪")
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// newAutoClient 创建无凭证客户端并启动（打开软件即自动注册），等待完全就绪。
func newAutoClient(t *testing.T, addr, name, hwid string, onCred func(id, key, nk string) error) (*Client, *mockTun) {
	t.Helper()
	tun := newMockTun(name)
	c := NewClient(Config{Server: addr, Name: name, HWID: hwid, NoPunch: true, OnCredential: onCred})
	c.newTun = func() (Tun, error) { return tun, nil }
	go c.Run()
	t.Cleanup(c.Close)
	waitVIP(t, c)
	waitReady(t, c)
	return c, tun
}

// TestAutoRegisterFlowAndDataPath 自动注册全链路：打开软件按 HWID 自动注册
// -> 凭证认证上线 -> 数据面互通，两台设备凭证相互独立。
func TestAutoRegisterFlowAndDataPath(t *testing.T) {
	srv, addr := startAuthServer(t)

	var savedA, savedB [3]string
	ca, ta := newAutoClient(t, addr, "ca", "hwid-reg-a", func(id, key, nk string) error {
		savedA = [3]string{id, key, nk}
		return nil
	})
	cb, tb := newAutoClient(t, addr, "cb", "hwid-reg-b", func(id, key, nk string) error {
		savedB = [3]string{id, key, nk}
		return nil
	})

	// 凭证必须已签发并保存
	for i, c := range []*Client{ca, cb} {
		if c.cfg.DeviceKey == "" || c.cfg.DeviceID == "" || c.cfg.NetworkKey == "" {
			t.Fatalf("客户端 %d 未获得完整凭证", i)
		}
	}
	if savedA[0] == "" || savedA[0] != ca.cfg.DeviceID {
		t.Fatal("OnCredential 回调未收到凭证")
	}
	if savedA[1] == savedB[1] {
		t.Fatal("两台设备的密钥不应相同（每设备独立凭证）")
	}

	// 数据面互通（双方强制中继）
	aVIP, bVIP := ca.self.Load(), cb.self.Load()
	req := icmpEcho(bVIP, aVIP, 7, 7)
	tb.in <- req
	if got := waitOut(t, ta); string(got) != string(req) {
		t.Fatalf("自动注册网络数据面不通（bob->alice）")
	}
	rep := icmpEcho(aVIP, bVIP, 7, 7)
	rep[20] = 0
	binary.BigEndian.PutUint16(rep[22:24], checksum(rep[20:]))
	ta.in <- rep
	if got := waitOut(t, tb); string(got) != string(rep) {
		t.Fatalf("自动注册网络数据面不通（alice->bob）")
	}
	_ = srv
}

// TestAutoRegisterReusesCredential 同一台设备（同一 HWID）重装系统/删除配置后
// 再连接，自动注册必须复用服务端已存的凭证，而不是换发新的。
func TestAutoRegisterReusesCredential(t *testing.T) {
	_, addr := startAuthServer(t)

	var saved [3]string
	c1, _ := newAutoClient(t, addr, "ca", "hwid-reuse", func(id, key, nk string) error {
		saved = [3]string{id, key, nk}
		return nil
	})
	c1.Close()

	// 模拟重装：新客户端没有任何凭证，仅凭同一 HWID 再连
	c2, _ := newAutoClient(t, addr, "ca", "hwid-reuse", nil)
	if c2.cfg.DeviceID != saved[0] || c2.cfg.DeviceKey != saved[1] || c2.cfg.NetworkKey != saved[2] {
		t.Fatalf("同 HWID 再注册应复用原凭证，实际 id=%s nk=%s", c2.cfg.DeviceID, c2.cfg.NetworkKey)
	}
}

// TestAutoRegisterBlockedAfterRevoke 管理页「清除凭证」现在会顺带封禁设备：
// 持有旧凭证的客户端重连应被服务端拒绝（认证失败后自动注册也被拒），
// 直到管理员「解除封禁」后才重新注册并拿到新凭证。
func TestAutoRegisterBlockedAfterRevoke(t *testing.T) {
	srv, addr := startAuthServer(t)

	var saved [3]string
	calls := 0
	ca, _ := newAutoClient(t, addr, "ca", "hwid-block", func(id, key, nk string) error {
		calls++
		if calls == 1 {
			saved = [3]string{id, key, nk}
		}
		return nil
	})
	ca.Close()

	// 管理页清除凭证（= 清凭证 + 封禁）
	if !srv.RevokeDeviceCredential("hwid-block") {
		t.Fatal("清除凭证应成功")
	}

	// 封禁期间用旧凭证重连：拿不到虚拟 IP
	re := NewClient(Config{Server: addr, DeviceID: saved[0], DeviceKey: saved[1], NetworkKey: saved[2],
		Name: "ca", HWID: "hwid-block", NoPunch: true})
	re.newTun = func() (Tun, error) { return newMockTun("ca"), nil }
	go re.Run()
	t.Cleanup(re.Close)
	time.Sleep(1500 * time.Millisecond)
	if v := re.self.Load(); v != 0 {
		t.Fatalf("封禁期间不应获得虚拟 IP，实际 %s", protocol.IP4String(v))
	}

	// 管理员解除封禁后：客户端应自动重新注册并上线
	if !srv.UnblockDevice("hwid-block") {
		t.Fatal("解除封禁应成功")
	}
	waitVIP(t, re)
	waitReady(t, re)
	if re.cfg.DeviceID == "" || re.cfg.DeviceID == saved[0] {
		t.Fatalf("解封后重新注册应换发新凭证，实际 id=%s 旧=%s", re.cfg.DeviceID, saved[0])
	}
}

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"sulink-lan/internal/protocol"
)

// startTestServer 启动一个使用随机端口的服务器（端口填 0，由 Addr() 返回实际地址，无 TOCTOU）。
func startTestServer(t *testing.T) (addr string, cancel context.CancelFunc) {
	t.Helper()
	srv, err := New(Config{TCPAddr: "127.0.0.1:0", UDPAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go srv.Run(ctx)
	t.Cleanup(c)
	deadline := time.Now().Add(3 * time.Second)
	for {
		addr = srv.Addr()
		if addr != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("服务器未就绪")
		}
		time.Sleep(30 * time.Millisecond)
	}
	return addr, c
}

// fakeClient 模拟一个客户端：TCP 信令（自动注册 + 设备凭证认证）+ UDP 数据。
type fakeClient struct {
	t      *testing.T
	crypto *protocol.Crypto
	tcp    net.Conn
	udp    *net.UDPConn
	VIP    uint32
	// LeaseUntil 服务端在 Welcome 里给出的租约到期时刻（Unix 秒）。
	LeaseUntil int64
}

// newFakeClientHWID 创建一台设备：打开软件即自动注册，随后用设备凭证重连认证。
// 与真实客户端的行为一致——注册与认证分离，注册成功后服务端关闭连接。
func newFakeClientHWID(t *testing.T, addr, name, hwid string) *fakeClient {
	t.Helper()
	if hwid == "" {
		hwid = "hwid-" + name
	}
	// 1) 自动注册：HWID 应答挑战 -> 服务端签发/复用凭证（按 HWID 加密回传）
	reg, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	reg.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := protocol.ReadMsg(reg)
	if err != nil || m.Type != protocol.MsgChallenge || len(m.Nonce) == 0 {
		t.Fatalf("未收到认证挑战: %v %+v", err, m)
	}
	if err := protocol.WriteMsg(reg, &protocol.Message{
		Type:       protocol.MsgRegister,
		DeviceName: name,
		HWID:       hwid,
		Auth:       protocol.AuthTagFor(protocol.RegisterAuthKey(hwid), m.Nonce),
	}); err != nil {
		t.Fatal(err)
	}
	m, err = protocol.ReadMsg(reg)
	if err != nil || m.Type != protocol.MsgRegisterOK || len(m.Blob) == 0 {
		t.Fatalf("自动注册失败: %v %+v", err, m)
	}
	cred, err := protocol.DecryptCredential(hwid, m.Blob)
	if err != nil {
		t.Fatalf("注册响应解密失败: %v", err)
	}
	reg.Close()

	// 2) 凭证认证重连：数据面用网络密钥，信令认证用设备密钥派生键
	netKey, err := protocol.ParseKey(cred.NetworkKey)
	if err != nil {
		t.Fatal(err)
	}
	devKey, err := protocol.ParseKey(cred.DeviceKey)
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := protocol.NewCryptoWithKeys(netKey, protocol.DeviceAuthKey(devKey))
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tcp.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err = protocol.ReadMsg(tcp)
	if err != nil || m.Type != protocol.MsgChallenge || len(m.Nonce) == 0 {
		t.Fatalf("未收到认证挑战: %v %+v", err, m)
	}
	if err := protocol.WriteMsg(tcp, &protocol.Message{
		Type:       protocol.MsgHello,
		DeviceName: name,
		HWID:       hwid,
		DeviceID:   cred.DeviceID,
		Auth:       crypto.AuthTag(m.Nonce),
	}); err != nil {
		t.Fatal(err)
	}
	m, err = protocol.ReadMsg(tcp)
	if err != nil || m.Type != protocol.MsgWelcome {
		t.Fatalf("welcome failed: %v %+v", err, m)
	}
	fc := &fakeClient{t: t, crypto: crypto, tcp: tcp, VIP: m.VIP, LeaseUntil: m.LeaseUntil}
	if fc.VIP == 0 {
		t.Fatal("未分配到虚拟 IP")
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	fc.udp = udp

	// UDP 注册（加密探测包），服务器验证后记录 NAT 地址并把包弹回作为确认
	probe, err := crypto.Encrypt(protocol.FlagProbe, fc.VIP, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	srvUDP, _ := net.ResolveUDPAddr("udp", addr)
	if _, err := udp.WriteToUDP(probe, srvUDP); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(time.Second))
	rbuf := make([]byte, protocol.MaxPacket)
	if _, _, err := udp.ReadFromUDP(rbuf); err != nil {
		t.Fatalf("服务器未确认 UDP 注册: %v", err)
	}

	// 读 PeerList（清掉）
	if m, err := protocol.ReadMsg(tcp); err != nil || m.Type != protocol.MsgPeerList {
		t.Fatalf("peerlist failed: %v", m)
	}
	return fc
}

// newFakeClient 创建一个以设备名为 HWID 的模拟客户端（每台测试设备一个独立标识）。
func newFakeClient(t *testing.T, addr, name string) *fakeClient {
	t.Helper()
	return newFakeClientHWID(t, addr, name, "hwid-"+name)
}

func (fc *fakeClient) readMsg(t *testing.T) *protocol.Message {
	t.Helper()
	for {
		fc.tcp.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, err := protocol.ReadMsg(fc.tcp)
		if err != nil {
			t.Fatalf("read msg: %v", err)
		}
		// 跳过上线/列表广播
		if m.Type == protocol.MsgPeerOnline || m.Type == protocol.MsgPeerList {
			continue
		}
		return m
	}
}

func (fc *fakeClient) close() {
	fc.tcp.Close()
	fc.udp.Close()
}

// TestAuthReject 回归验证信令认证：无设备凭证、未知凭证或错误认证标签的
// 连接被拒绝，无法上线、无法获取设备列表（防枚举 / 防 IP 池耗尽）。
func TestAuthReject(t *testing.T) {
	addr, _ := startTestServer(t)

	// 1) 未知设备凭证 + 伪造认证标签：能通过挑战流程但查表即拒
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := protocol.ReadMsg(conn)
	if err != nil || m.Type != protocol.MsgChallenge {
		t.Fatalf("未收到挑战: %v %+v", err, m)
	}
	if err := protocol.WriteMsg(conn, &protocol.Message{
		Type:       protocol.MsgHello,
		DeviceName: "intruder",
		DeviceID:   "NONEXISTENTDEVICEID00000000000",
		Auth:       bytes.Repeat([]byte{0x42}, 32),
	}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err = protocol.ReadMsg(conn)
	if err != nil {
		t.Fatalf("服务器未回应: %v", err)
	}
	if m.Type != protocol.MsgError {
		t.Fatalf("BUG 回归：未知凭证竟然注册成功: %+v", m)
	}

	// 2) 完全不带凭证（无 DeviceID）的 Hello 同样被拒绝
	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if m, err := protocol.ReadMsg(conn2); err != nil || m.Type != protocol.MsgChallenge {
		t.Fatalf("未收到挑战: %v", err)
	}
	if err := protocol.WriteMsg(conn2, &protocol.Message{Type: protocol.MsgHello, DeviceName: "intruder2"}); err != nil {
		t.Fatal(err)
	}
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err = protocol.ReadMsg(conn2)
	if err != nil {
		t.Fatalf("服务器未回应: %v", err)
	}
	if m.Type != protocol.MsgError {
		t.Fatalf("BUG 回归：无凭证 Hello 竟然注册成功: %+v", m)
	}

	// 3) 正常客户端随后仍可注册（服务器未被污染）
	ok := newFakeClient(t, addr, "legit")
	defer ok.close()
	if ok.VIP == 0 {
		t.Fatal("合法客户端注册失败")
	}
}

// TestRelayForward 验证：UDP 中继按目标 VIP 转发加密数据包。
func TestRelayForward(t *testing.T) {
	addr, _ := startTestServer(t)
	a := newFakeClient(t, addr, "aa")
	defer a.close()
	b := newFakeClient(t, addr, "bb")
	defer b.close()

	// a 向服务器发加密 Data 包（dst = b 的 VIP），期待 b 收到原始密文
	srvUDP, _ := net.ResolveUDPAddr("udp", addr)
	payload := []byte("hello-sulink-relay")
	pkt, err := a.crypto.Encrypt(protocol.FlagData, a.VIP, b.VIP, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.udp.WriteToUDP(pkt, srvUDP); err != nil {
		t.Fatal(err)
	}

	b.udp.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, protocol.MaxPacket)
	var n int
	for {
		var err error
		n, _, err = b.udp.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("b 未收到中继数据: %v", err)
		}
		if n < protocol.HeaderLen {
			continue
		}
		// 跳过注册探测包的回弹
		if buf[0]&0xF0 != protocol.FlagData {
			continue
		}
		break
	}
	// 服务器应原样转发密文
	if !bytes.Equal(buf[:n], pkt) {
		t.Fatalf("中继包内容不一致")
	}
	// 解密后校验内容
	got, err := b.crypto.Decrypt(buf[:n])
	if err != nil {
		t.Fatalf("中继包解密失败: %v", err)
	}
	if got.Dest != b.VIP || string(got.Data) != string(payload) {
		t.Fatalf("payload mismatch: dst=%s data=%q", protocol.IP4String(got.Dest), got.Data)
	}
}

// TestRelayRejectForged 回归验证中继防伪造：
// 伪造 src VIP 的明文包（无法通过 AES-GCM 认证）必须被服务器丢弃，
// 既不转发也不污染目标设备的 UDPAddr 记录。
func TestRelayRejectForged(t *testing.T) {
	addr, _ := startTestServer(t)
	a := newFakeClient(t, addr, "aa")
	defer a.close()
	b := newFakeClient(t, addr, "bb")
	defer b.close()

	// 伪造：明文头 src=aa 的 VIP，载荷为垃圾（无有效 GCM 标签）
	forged := make([]byte, protocol.HeaderLen+8)
	forged[0] = protocol.FlagData
	binary.BigEndian.PutUint32(forged[1:5], a.VIP)
	binary.BigEndian.PutUint32(forged[5:9], b.VIP)
	copy(forged[protocol.HeaderLen:], []byte("garbage!"))

	srvUDP, _ := net.ResolveUDPAddr("udp", addr)
	if _, err := a.udp.WriteToUDP(forged, srvUDP); err != nil {
		t.Fatal(err)
	}
	// 多发几次以防时序偏差
	for i := 0; i < 3; i++ {
		a.udp.WriteToUDP(forged, srvUDP)
	}

	// b 不应收到任何 Data 包
	b.udp.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	buf := make([]byte, protocol.MaxPacket)
	for {
		n, _, err := b.udp.ReadFromUDP(buf)
		if err != nil {
			break // 超时：没有数据包到达，符合预期
		}
		if n >= protocol.HeaderLen && buf[0]&0xF0 == protocol.FlagData {
			t.Fatalf("BUG 回归：伪造包被中继转发")
		}
	}

	// 合法加密流量仍然正常转发（服务器状态未被污染）
	payload := []byte("still-works")
	pkt, err := a.crypto.Encrypt(protocol.FlagData, a.VIP, b.VIP, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.udp.WriteToUDP(pkt, srvUDP); err != nil {
		t.Fatal(err)
	}
	b.udp.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err := b.udp.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("合法流量被误伤: %v", err)
		}
		if n >= protocol.HeaderLen && buf[0]&0xF0 == protocol.FlagData {
			break
		}
	}
}

// TestRelayBroadcast 验证：发往网段定向广播地址（10.255.255.255）的数据包
// 被泛洪给所有在线设备，且不回给发送者本人。
//
// 回归背景：三层隧道只转发单播，广播包按目标 VIP 查表必然落空而被静默丢弃，
// 表现为「虚拟局域网内互相发现不了」。
func TestRelayBroadcast(t *testing.T) {
	addr, _ := startTestServer(t)
	a := newFakeClient(t, addr, "bc-a")
	defer a.close()
	b := newFakeClient(t, addr, "bc-b")
	defer b.close()
	c := newFakeClient(t, addr, "bc-c")
	defer c.close()

	srvUDP, _ := net.ResolveUDPAddr("udp", addr)
	payload := []byte("lan-discovery")
	pkt, err := a.crypto.Encrypt(protocol.FlagData, a.VIP, protocol.VNetBroadcast, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.udp.WriteToUDP(pkt, srvUDP); err != nil {
		t.Fatal(err)
	}

	// b、c 都应收到原样密文
	for i, fc := range []*fakeClient{b, c} {
		fc.udp.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, protocol.MaxPacket)
		for {
			n, _, err := fc.udp.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("广播未送达第 %d 个对端: %v", i+1, err)
			}
			if n < protocol.HeaderLen || buf[0]&0xF0 != protocol.FlagData {
				continue // 跳过注册探测包的回弹
			}
			if !bytes.Equal(buf[:n], pkt) {
				t.Fatal("广播包不是原样密文")
			}
			got, err := fc.crypto.Decrypt(buf[:n])
			if err != nil {
				t.Fatalf("广播包解密失败: %v", err)
			}
			if got.Dest != protocol.VNetBroadcast {
				t.Fatalf("广播目标地址被改写: %s", protocol.IP4String(got.Dest))
			}
			if string(got.Data) != string(payload) {
				t.Fatalf("广播载荷不一致: %q", got.Data)
			}
			break
		}
	}

	// 对照 1：发送者本人不应收到自己的广播（否则会形成回环放大）
	a.udp.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	buf := make([]byte, protocol.MaxPacket)
	for {
		n, _, err := a.udp.ReadFromUDP(buf)
		if err != nil {
			break // 超时：符合预期
		}
		if n >= protocol.HeaderLen && buf[0]&0xF0 == protocol.FlagData {
			t.Fatal("发送者收到了自己的广播包")
		}
	}

	// 对照 2：未注册的源 VIP 不得触发泛洪。
	// 泛洪是一次「一对多」放大，若能凭一个可解密的包触发，
	// 就等于给已注册设备留了个廉价的刷量入口。
	ghost, err := protocol.IP4("10.0.0.99") // 从未分配过的地址
	if err != nil {
		t.Fatal(err)
	}
	forged, err := a.crypto.Encrypt(protocol.FlagData, ghost, protocol.VNetBroadcast, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.udp.WriteToUDP(forged, srvUDP); err != nil {
		t.Fatal(err)
	}
	for i, fc := range []*fakeClient{b, c} {
		fc.udp.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
		for {
			n, _, err := fc.udp.ReadFromUDP(buf)
			if err != nil {
				break // 超时：符合预期
			}
			if n >= protocol.HeaderLen && buf[0]&0xF0 == protocol.FlagData {
				t.Fatalf("第 %d 个对端收到了未注册源发起的广播", i+1)
			}
		}
	}
}

// TestHolePunchSignaling 验证：打洞信令把双方候选地址互发。
func TestHolePunchSignaling(t *testing.T) {
	addr, _ := startTestServer(t)
	a := newFakeClient(t, addr, "hole-a")
	defer a.close()
	b := newFakeClient(t, addr, "hole-b")
	defer b.close()

	// a 请求与 b 打洞
	if err := protocol.WriteMsg(a.tcp, &protocol.Message{Type: protocol.MsgHoleRequest, PeerVIP: b.VIP}); err != nil {
		t.Fatal(err)
	}
	// a 收到 b 的候选地址
	ma := a.readMsg(t)
	if ma.Type != protocol.MsgHoleNotify || len(ma.Addrs) == 0 {
		t.Fatalf("a 未收到 hole notify: %+v", ma)
	}
	// b 收到 a 的候选地址
	mb := b.readMsg(t)
	if mb.Type != protocol.MsgHoleNotify || len(mb.Addrs) == 0 {
		t.Fatalf("b 未收到 hole notify: %+v", mb)
	}
	if ma.PeerVIP != b.VIP || mb.PeerVIP != a.VIP {
		t.Fatalf("peer vip mismatch: %x %x", ma.PeerVIP, mb.PeerVIP)
	}
}

// TestOfflineNotify 验证：设备下线后广播通知并释放注册。
func TestOfflineNotify(t *testing.T) {
	addr, _ := startTestServer(t)
	a := newFakeClient(t, addr, "off-a")
	b := newFakeClient(t, addr, "off-b")
	defer b.close()

	aVIP := a.VIP
	a.close()
	// b 应收到 a 下线通知
	b.tcp.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		m, err := protocol.ReadMsg(b.tcp)
		if err != nil {
			t.Fatalf("b 未收到下线通知: %v", err)
		}
		if m.Type == protocol.MsgPeerOffline && m.PeerVIP == aVIP {
			break
		}
	}
	// a 的名字应可重新注册
	c := newFakeClient(t, addr, "off-a")
	defer c.close()
	if c.VIP == 0 {
		t.Fatal("重新注册失败")
	}
}

package server

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"sulink-lan/internal/protocol"
)

// ---- 构造测试报文 ----

// icmpEcho 构造一个带完整 IPv4 头的 ICMP echo 报文。
func icmpEcho(src, dst uint32, id, seq uint16, typ byte) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = ipProtoICMP
	binary.BigEndian.PutUint32(pkt[12:16], src)
	binary.BigEndian.PutUint32(pkt[16:20], dst)
	pkt[20] = typ
	pkt[21] = 0
	binary.BigEndian.PutUint16(pkt[22:24], 0)
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	binary.BigEndian.PutUint16(pkt[22:24], checksum(pkt[20:]))
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	return pkt
}

// assertValidIPv4 校验 IP 头与 ICMP 校验和：校验和正确时整段反码求和为 0。
func assertValidIPv4(t *testing.T, pkt []byte) {
	t.Helper()
	ihl := ipv4HeaderLen(pkt)
	if ihl == 0 {
		t.Fatal("不是合法的 IPv4 包")
	}
	if checksum(pkt[:ihl]) != 0 {
		t.Fatal("IP 头校验和不正确")
	}
	if checksum(pkt[ihl:]) != 0 {
		t.Fatal("ICMP 校验和不正确")
	}
}

const (
	testSrvVIP = uint32(0x0A000001) // 10.0.0.1
	testCliVIP = uint32(0x0A000002) // 10.0.0.2
)

// TestEchoReply 单元验证应答判定与合成：只对「发往服务器 VIP 的 ICMPv4
// echo request」作出应答，其余包一律不碰。
func TestEchoReply(t *testing.T) {
	t.Run("正常 echo request 生成正确应答", func(t *testing.T) {
		req := icmpEcho(testCliVIP, testSrvVIP, 0x1234, 7, icmpEchoRequest)
		rep, ok := echoReply(req, testSrvVIP)
		if !ok {
			t.Fatal("未生成应答")
		}
		ihl := ipv4HeaderLen(rep)
		if rep[ihl] != icmpEchoReply {
			t.Fatalf("ICMP 类型应为 echo reply(0)，实际 %d", rep[ihl])
		}
		// 地址互换：应答源=服务器 VIP，目的=请求方
		if got := binary.BigEndian.Uint32(rep[12:16]); got != testSrvVIP {
			t.Fatalf("应答源地址应为 %s，实际 %s", protocol.IP4String(testSrvVIP), protocol.IP4String(got))
		}
		if got := binary.BigEndian.Uint32(rep[16:20]); got != testCliVIP {
			t.Fatalf("应答目的地址应为 %s，实际 %s", protocol.IP4String(testCliVIP), protocol.IP4String(got))
		}
		// id/seq 必须原样带回，否则 ping 无法匹配请求
		if binary.BigEndian.Uint16(rep[ihl+4:ihl+6]) != 0x1234 ||
			binary.BigEndian.Uint16(rep[ihl+6:ihl+8]) != 7 {
			t.Fatal("应答未回显 id/seq")
		}
		assertValidIPv4(t, rep)
	})

	t.Run("DF 位置位仍应应答", func(t *testing.T) {
		req := icmpEcho(testCliVIP, testSrvVIP, 1, 1, icmpEchoRequest)
		binary.BigEndian.PutUint16(req[6:8], 0x4000) // DF
		binary.BigEndian.PutUint16(req[10:12], 0)
		binary.BigEndian.PutUint16(req[10:12], checksum(req[:20]))
		if _, ok := echoReply(req, testSrvVIP); !ok {
			t.Fatal("带 DF 位的 echo request 被错误拒绝（会导致部分系统 ping 不通）")
		}
	})

	reject := []struct {
		name string
		pkt  func() []byte
	}{
		{"分片包不应答", func() []byte {
			p := icmpEcho(testCliVIP, testSrvVIP, 1, 1, icmpEchoRequest)
			binary.BigEndian.PutUint16(p[6:8], 0x2000) // MF
			return p
		}},
		{"非首片不应答", func() []byte {
			p := icmpEcho(testCliVIP, testSrvVIP, 1, 1, icmpEchoRequest)
			binary.BigEndian.PutUint16(p[6:8], 8) // 分片偏移
			return p
		}},
		{"目标不是服务器 VIP 不应答", func() []byte {
			return icmpEcho(testCliVIP, testCliVIP+1, 1, 1, icmpEchoRequest)
		}},
		{"echo reply 不应答", func() []byte {
			return icmpEcho(testCliVIP, testSrvVIP, 1, 1, icmpEchoReply)
		}},
		{"非 ICMP 协议不应答", func() []byte {
			p := icmpEcho(testCliVIP, testSrvVIP, 1, 1, icmpEchoRequest)
			p[9] = 6 // TCP
			binary.BigEndian.PutUint16(p[10:12], 0)
			binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
			return p
		}},
		{"ICMP code 非 0 不应答", func() []byte {
			p := icmpEcho(testCliVIP, testSrvVIP, 1, 1, icmpEchoRequest)
			p[21] = 1
			return p
		}},
		{"长度不足不应答", func() []byte {
			return icmpEcho(testCliVIP, testSrvVIP, 1, 1, icmpEchoRequest)[:24]
		}},
		{"总长度字段撒谎不应答", func() []byte {
			p := icmpEcho(testCliVIP, testSrvVIP, 1, 1, icmpEchoRequest)
			binary.BigEndian.PutUint16(p[2:4], 4) // total < ihl
			return p
		}},
		{"空包不应答", func() []byte { return nil }},
		{"非 IPv4 不应答", func() []byte { return []byte{0x60, 0, 0, 0} }},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := echoReply(tc.pkt(), testSrvVIP); ok {
				t.Fatal("不该生成应答")
			}
		})
	}
}

// TestPingServerVIP 回归验证：客户端 ping 服务器虚拟 IP 必须收到应答。
//
// 修复前，服务端中继循环只在目标 VIP 已注册时才转发，而服务器自身从不注册，
// 于是发往 10.0.0.1 的包被静默丢弃——表现为「隧道已连通，ping 网关却永远超时」。
func TestPingServerVIP(t *testing.T) {
	addr, _ := startTestServer(t)
	a := newFakeClient(t, addr, "ping-a")
	defer a.close()

	srvUDP, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, protocol.MaxPacket)

	// 1) ping 服务器 VIP：必须收到 echo reply
	req := icmpEcho(a.VIP, testSrvVIP, 0x4321, 1, icmpEchoRequest)
	pkt, err := a.crypto.Encrypt(protocol.FlagData, a.VIP, testSrvVIP, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.udp.WriteToUDP(pkt, srvUDP); err != nil {
		t.Fatal(err)
	}

	a.udp.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := false
	for !got {
		n, _, err := a.udp.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("BUG 回归：ping 服务器虚拟 IP %s 无应答: %v",
				protocol.IP4String(testSrvVIP), err)
		}
		if n < protocol.HeaderLen || buf[0]&0xF0 != protocol.FlagData {
			continue // 跳过注册探测包的回弹
		}
		p, err := a.crypto.Decrypt(buf[:n])
		if err != nil {
			t.Fatalf("应答解密失败: %v", err)
		}
		if p.Source != testSrvVIP || p.Dest != a.VIP {
			t.Fatalf("应答地址错误: src=%s dst=%s",
				protocol.IP4String(p.Source), protocol.IP4String(p.Dest))
		}
		ihl := ipv4HeaderLen(p.Data)
		if ihl == 0 || p.Data[9] != ipProtoICMP {
			t.Fatalf("应答不是 ICMP 包")
		}
		if p.Data[ihl] != icmpEchoReply {
			t.Fatalf("ICMP 类型应为 echo reply(0)，实际 %d", p.Data[ihl])
		}
		if binary.BigEndian.Uint32(p.Data[12:16]) != testSrvVIP ||
			binary.BigEndian.Uint32(p.Data[16:20]) != a.VIP {
			t.Fatal("应答 IP 头地址未正确互换")
		}
		if binary.BigEndian.Uint16(p.Data[ihl+4:ihl+6]) != 0x4321 {
			t.Fatal("应答未回显 ping 的 id")
		}
		assertValidIPv4(t, p.Data)
		got = true
	}

	// 2) 对照：发往一个未注册的虚拟 IP 不得有任何应答，
	//    否则说明服务端变成了「什么都回」，上一步的通过就是假通过。
	ghost := testSrvVIP + 100
	req2 := icmpEcho(a.VIP, ghost, 0x4321, 2, icmpEchoRequest)
	pkt2, err := a.crypto.Encrypt(protocol.FlagData, a.VIP, ghost, req2)
	if err != nil {
		t.Fatal(err)
	}
	a.udp.WriteToUDP(pkt2, srvUDP)
	a.udp.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	for {
		n, _, err := a.udp.ReadFromUDP(buf)
		if err != nil {
			break // 超时：符合预期
		}
		if n >= protocol.HeaderLen && buf[0]&0xF0 == protocol.FlagData {
			t.Fatalf("不存在的虚拟 IP %s 竟然收到应答", protocol.IP4String(ghost))
		}
	}
}

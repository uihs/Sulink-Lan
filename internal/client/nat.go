package client

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"sulink-lan/internal/forward"
)

// 内网穿透：把"虚拟网络内访问 本机虚拟IP:VPort"的 TCP/UDP 流量，
// DNAT 转发到内网目标 IP:Port，并对回包做反向 SNAT（conntrack）。
// 仅处理 IPv4。

// ForwardRule 一条内网穿透规则：虚拟端口 -> 内网目标。
//
// 用类型别名而不是在这里重新定义一份结构：规则格式是客户端本地配置与服务端
// 下发配置共用的约定，同一个类型才能保证两边的解析结果可以直接互换。
type ForwardRule = forward.Rule

// Nat 三层 NAT + 连接跟踪。
type Nat struct {
	self    uint32 // 本机虚拟 IP
	rules   map[uint16]ForwardRule
	mu      sync.Mutex
	fwd     map[flowKey]*flowEntry // 请求方向 -> 内网目标
	rev     map[flowKey]uint16     // 响应方向 -> 虚拟端口
	revSeen map[flowKey]time.Time  // 响应方向条目的最后活跃时间
	done    chan struct{}          // 关闭信号（停止清理协程）
	once    sync.Once              // Close 幂等
}

type flowKey struct {
	proto   uint8
	srcIP   uint32
	srcPort uint16
	dstIP   uint32
	dstPort uint16
}

type flowEntry struct {
	targetIP   uint32
	targetPort uint16
	lastSeen   time.Time
}

// NewNat 创建 NAT。
func NewNat(self uint32, rules []ForwardRule) *Nat {
	n := &Nat{
		self:    self,
		rules:   make(map[uint16]ForwardRule),
		fwd:     make(map[flowKey]*flowEntry),
		rev:     make(map[flowKey]uint16),
		revSeen: make(map[flowKey]time.Time),
		done:    make(chan struct{}),
	}
	for _, r := range rules {
		n.rules[r.VPort] = r
	}
	go n.cleanLoop()
	return n
}

// Close 停止清理协程（幂等）。客户端每轮重连都会重建 NAT，
// 不关闭旧实例的清理协程会导致 goroutine 泄漏。
func (n *Nat) Close() {
	n.once.Do(func() { close(n.done) })
}

// DNAT 处理发往本机虚拟 IP 的 IP 包：若命中穿透规则，改写目标地址。
// 返回是否已改写（改写后调用方需将包写回 TUN 让内核路由到内网）。
func (n *Nat) DNAT(buf []byte) bool {
	p, ok := parseIPv4(buf)
	if !ok || (p.proto != 6 && p.proto != 17) {
		return false
	}
	if p.dst != n.self {
		return false
	}
	dstPort := p.dstPort()
	now := time.Now()
	// 规则表必须在锁内读取：服务端可以在运行中整体替换规则（SetRules），
	// 而 DNAT 在中继热路径上。早期规则创建后不再变化，读取没加锁；
	// 现在加了替换入口，不加锁就是一次真实的数据竞争。
	n.mu.Lock()
	rule, hit := n.rules[dstPort]
	// 传输层头不完整（畸形包把 IP total 写成小于 头长+最小传输层头）时不得命中：
	// 这类包写回 TUN 也只会被内核丢弃，命中反而给攻击者一个「探测端口是否开放」的侧信道。
	if hit && !p.transportOK() {
		hit = false
	}
	if hit {
		// 请求方向：{proto, 客户端IP, 客户端端口, 本机VIP, 虚拟端口} -> 内网目标
		fk := flowKey{proto: p.proto, srcIP: p.src, srcPort: p.srcPort(), dstIP: n.self, dstPort: dstPort}
		// 响应方向：{proto, 内网目标IP, 内网目标端口, 客户端IP, 客户端端口} -> 虚拟端口
		rk := flowKey{proto: p.proto, srcIP: rule.TargetIP, srcPort: rule.TargetPort, dstIP: p.src, dstPort: p.srcPort()}
		n.fwd[fk] = &flowEntry{targetIP: rule.TargetIP, targetPort: rule.TargetPort, lastSeen: now}
		n.rev[rk] = dstPort
		n.revSeen[rk] = now
	}
	n.mu.Unlock()
	if !hit {
		return false
	}
	// DNAT：改写目标 IP 与目标端口（虚拟端口 -> 内网目标端口），
	// 二者都必须改写，否则"虚拟端口 != 目标端口"的映射规则不生效。
	p.setDst(rule.TargetIP)
	p.setDstPort(rule.TargetPort)
	rewriteChecksums(buf)
	return true
}

// SetRules 整体替换穿透规则（服务端下发时调用）。
//
// 整体替换而不是合并：服务端每次下发的都是该设备的完整规则集，
// 合并会让管理页删掉的规则永远残留。
//
// 不清空既有的连接跟踪条目：它们会随「2 分钟无流量」自然过期，
// 而正在传输的会话不该因为一次规则调整被掐断。
func (n *Nat) SetRules(rules []ForwardRule) {
	next := make(map[uint16]ForwardRule, len(rules))
	for _, r := range rules {
		next[r.VPort] = r
	}
	n.mu.Lock()
	n.rules = next
	n.mu.Unlock()
}

// SNAT 处理从 TUN 读出的响应包：内网目标回包的源地址改回本机虚拟 IP。
// 返回是否已改写。
func (n *Nat) SNAT(buf []byte) bool {
	p, ok := parseIPv4(buf)
	if !ok || (p.proto != 6 && p.proto != 17) {
		return false
	}
	rk := flowKey{proto: p.proto, srcIP: p.src, srcPort: p.srcPort(), dstIP: p.dst, dstPort: p.dstPort()}
	n.mu.Lock()
	vPort, hit := n.rev[rk]
	// 与 DNAT 一致：传输层头不完整的包不命中（rev 表只由 DNAT 写入，
	// 但这里仍要防御，避免畸形回包走改写路径）。
	if hit && !p.transportOK() {
		hit = false
	}
	if hit {
		n.revSeen[rk] = time.Now()
	}
	n.mu.Unlock()
	if !hit {
		return false
	}
	// SNAT：源 IP 改回本机虚拟 IP，源端口改回虚拟端口
	p.setSrc(n.self)
	p.setSrcPort(vPort)
	rewriteChecksums(buf)
	return true
}

// cleanLoop 定期清理过期连接跟踪条目；Nat.Close 后退出。
func (n *Nat) cleanLoop() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-t.C:
		}
		now := time.Now()
		n.mu.Lock()
		for k, f := range n.fwd {
			if now.Sub(f.lastSeen) > 2*time.Minute {
				delete(n.fwd, k)
			}
		}
		for k, seen := range n.revSeen {
			if now.Sub(seen) > 2*time.Minute {
				delete(n.rev, k)
				delete(n.revSeen, k)
			}
		}
		n.mu.Unlock()
	}
}

// ---- IPv4 解析与校验和 ----

// ipv4Pkt 解析后的 IPv4 包关键字段。
type ipv4Pkt struct {
	buf   []byte
	proto uint8
	src   uint32
	dst   uint32
	ihl   int // 头长度（字节）
	total int // 总长度
}

func parseIPv4(buf []byte) (*ipv4Pkt, bool) {
	if len(buf) < 20 || buf[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl {
		return nil, false
	}
	total := int(binary.BigEndian.Uint16(buf[2:4]))
	if total > len(buf) {
		total = len(buf)
	}
	// 拒绝「声称总长度小于头长度」的畸形包：total 会被后续代码当切片上界用，
	// 不加校验会让 buf[ihl:total] 产生负长度切片，进而越界 panic。
	if total < ihl {
		return nil, false
	}
	return &ipv4Pkt{
		buf:   buf,
		proto: buf[9],
		src:   binary.BigEndian.Uint32(buf[12:16]),
		dst:   binary.BigEndian.Uint32(buf[16:20]),
		ihl:   ihl,
		total: total,
	}, true
}

// transportOK 报告 IP 包是否携带完整的传输层头（TCP 至少 20 字节，UDP 至少 8 字节）。
//
// 畸形包可把 IP 头的 total 字段写成任意值（如 total=24、ihl=20，声称 UDP 但
// 传输层头根本没到齐）。这类包必须被 NAT 拒之门外：改写它们既没有意义
// （写回 TUN 也会被内核丢弃），又会把「端口是否开放」变成可探测的侧信道。
func (p *ipv4Pkt) transportOK() bool {
	min := 0
	switch p.proto {
	case 6:
		min = 20 // TCP 最小头长
	case 17:
		min = 8 // UDP 头长
	default:
		return true // 非 TCP/UDP 由调用方另行处理
	}
	return p.total >= p.ihl+min
}

// srcPort / dstPort 读取 TCP/UDP 段端口（仅 proto 6/17）。
func (p *ipv4Pkt) srcPort() uint16 {
	if p.proto != 6 && p.proto != 17 || p.total < p.ihl+4 {
		return 0
	}
	return binary.BigEndian.Uint16(p.buf[p.ihl : p.ihl+2])
}

func (p *ipv4Pkt) dstPort() uint16 {
	if p.proto != 6 && p.proto != 17 || p.total < p.ihl+4 {
		return 0
	}
	return binary.BigEndian.Uint16(p.buf[p.ihl+2 : p.ihl+4])
}

// setSrc / setDst 改写 IP 地址字段（调用后需 rewriteChecksums）。
func (p *ipv4Pkt) setSrc(ip uint32) {
	binary.BigEndian.PutUint32(p.buf[12:16], ip)
	p.src = ip
}

func (p *ipv4Pkt) setDst(ip uint32) {
	binary.BigEndian.PutUint32(p.buf[16:20], ip)
	p.dst = ip
}

// setSrcPort 改写 TCP/UDP 源端口。
func (p *ipv4Pkt) setSrcPort(port uint16) {
	if p.proto != 6 && p.proto != 17 || p.total < p.ihl+4 {
		return
	}
	binary.BigEndian.PutUint16(p.buf[p.ihl:p.ihl+2], port)
}

// setDstPort 改写 TCP/UDP 目标端口。
func (p *ipv4Pkt) setDstPort(port uint16) {
	if p.proto != 6 && p.proto != 17 || p.total < p.ihl+4 {
		return
	}
	binary.BigEndian.PutUint16(p.buf[p.ihl+2:p.ihl+4], port)
}

// rewriteChecksums 重算 IPv4 头校验和与 TCP/UDP 校验和。
// 由于地址被改写，传输层校验和必须连同伪头部重新计算。
func rewriteChecksums(buf []byte) {
	p, ok := parseIPv4(buf)
	if !ok {
		return
	}
	// 1) IPv4 头校验和
	buf[10], buf[11] = 0, 0
	sum := checksum(buf[:p.ihl])
	buf[10], buf[11] = byte(sum>>8), byte(sum)

	// 2) TCP/UDP 校验和（伪头部随地址变化）
	seg := buf[p.ihl:p.total]
	if p.proto != 6 && p.proto != 17 {
		return
	}
	// UDP 校验和为 0 表示发送方不做校验（仅 IPv4 允许），此时无需重算。
	// 必须判断整个 16 位字段：早期实现写成 seg[6]&0x01 == 0，
	// 那只是在看校验和高字节的最低位，会把约一半的 UDP 包误判成「不校验」
	// 而跳过重算——地址已改、校验和没改，收端直接丢弃，
	// 表现为「UDP 穿透时通时不通」。此前测试只覆盖 TCP，没能拦住它。
	//
	// 读 seg[6]/seg[7] 前必须确认段长足够：畸形包可把 IP 头里的 total 字段
	// 写成只比头长多 4~6 字节（如 total=24、ihl=20），此时 UDP 头都没到齐，
	// 直接索引 seg[6] 会越界 panic，把整个客户端进程打崩（远端可构造）。
	if p.proto == 17 && len(seg) >= 8 && seg[6] == 0 && seg[7] == 0 {
		return
	}
	// 清零原校验和
	var csumOff int
	if p.proto == 6 {
		csumOff = 16
	} else {
		csumOff = 6
	}
	if len(seg) < csumOff+2 {
		return
	}
	seg[csumOff], seg[csumOff+1] = 0, 0
	pseudo := make([]byte, 12+len(seg))
	binary.BigEndian.PutUint32(pseudo[0:4], p.src)
	binary.BigEndian.PutUint32(pseudo[4:8], p.dst)
	pseudo[9] = p.proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	s := checksum(pseudo)
	seg[csumOff], seg[csumOff+1] = byte(s>>8), byte(s)
}

// rewriteDstToSelf 把 IP 包的目标地址改写为本机虚拟 IP，并重算校验和。
//
// 用途：把网段定向广播（10.255.255.255）交付给本机内核。
// 虚拟网卡配的是 /32——接口不「拥有」任何网段，也就没有主机位，
// 内核不会把 10.255.255.255 认作本接口的广播地址，包会被直接丢弃。
// 包明明已经送到我们进程里，却在最后一步被内核扔掉，所以先改成
// 本机地址再写回 TUN。发现类协议通常绑 0.0.0.0 收包，不受影响。
//
// 返回 false 表示不是可交付的 IPv4 包，调用方应丢弃。
func rewriteDstToSelf(buf []byte, self uint32) bool {
	p, ok := parseIPv4(buf)
	if !ok {
		return false
	}
	if p.dst == self {
		return true // 已是本机地址，无需改写
	}
	p.setDst(self)
	rewriteChecksums(buf)
	return true
}

// checksum 标准 Internet 校验和（16 位反码求和）。
func checksum(buf []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(buf); i += 2 {
		sum += uint32(buf[i])<<8 | uint32(buf[i+1])
	}
	if i < len(buf) {
		sum += uint32(buf[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// 工具：点分 IP 转 uint32。
func ip4u32(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, &net.AddrError{Err: "bad ipv4", Addr: s}
	}
	return binary.BigEndian.Uint32(ip), nil
}

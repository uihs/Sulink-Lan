package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sulink-lan/internal/forward"
	"sulink-lan/internal/hwid"
	"sulink-lan/internal/protocol"
)

// Config 客户端配置。
//
// 虚拟网段不在此处：它由 protocol.VNetCIDR 全网统一约定，
// 两端在地址空间上天然一致，不存在「配置不一致」这类故障。
//
// 内网穿透规则也不在此处：它由服务端按设备标识下发（MsgForwardPush）。
type Config struct {
	Server  string // 服务器地址 host:port
	Name    string // 本机设备名（同一服务器内唯一）
	NoPunch bool   // true 时禁用 P2P 打洞，强制走服务器中转
	MTU     int
	// 以下三字段是设备凭证，首次连接时由服务端按本机设备标识（HWID）自动
	// 签发、经 OnCredential 回调交给上层持久化；之后每次连接用它认证。
	//	DeviceID   设备凭证 ID（认证时明文上报，服务端查表）
	//	DeviceKey  设备密钥（hex，32 字节；泄露=设备身份被冒充）
	//	NetworkKey 数据面网络密钥（hex，32 字节；注册时加密下发）
	// 三者均为空时客户端会自动走注册流程（打开软件即自动注册）。
	DeviceID   string
	DeviceKey  string
	NetworkKey string
	// OnCredential 注册成功回调（可选）：上层把新凭证持久化到自己的配置
	// （GUI 写 config.json，CLI 写凭证文件）。失败只记日志不影响本次连接。
	OnCredential func(deviceID, deviceKey, networkKey string) error
	// HWID 显式指定设备标识；留空则自动取本机标识（internal/hwid）。
	//
	// 仅供测试与多实例调试使用：同一台机器上同时跑两个客户端时，
	// 它们会自动算出同一个设备标识，从而争抢同一个 IP 租约。
	// 刻意不通过命令行参数或配置文件对外暴露——设备标识决定 IP 归属，
	// 让它可被随手指定，等于把「冒领别人的地址」变成一条命令。
	HWID string
}

// peer 对端设备状态。
type peer struct {
	vip  uint32
	name string
	addr *net.UDPAddr // 实际通信地址（打洞成功后为对端公网地址）
	cand *net.UDPAddr // 服务器告知的候选地址
	p2p  bool         // P2P 是否打通
}

// Client 客户端。
type Client struct {
	cfg      Config
	crypto   *protocol.Crypto
	conn     net.Conn     // 信令 TCP
	udp      *net.UDPConn // 数据 UDP
	srvUDP   *net.UDPAddr
	tun      Tun
	self     atomic.Uint32 // 本机虚拟 IP（多 goroutine 读，用原子）
	net      *net.IPNet
	nat      *Nat
	peersMu  sync.Mutex
	peers    map[uint32]*peer
	punching map[uint32]bool
	writeMu  sync.Mutex    // 保护信令 TCP 连接写入（多 goroutine 并发写会损坏消息）
	session  chan struct{} // 会话结束信号（任一关键循环退出）
	closed   chan struct{} // 客户端整体关闭
	ready    chan struct{} // 会话就绪信号（注册/网卡/循环全部就绪后关闭）
	// newTun 创建虚拟网卡（默认 OpenTun；测试可注入内存网卡）
	newTun func() (Tun, error)

	// noPunch 是否禁止 P2P 打洞。用原子量而不是直接读 cfg.NoPunch：
	// 服务端可以在运行中下发「禁止打洞」，而信令循环正在并发读它。
	// 直接改 cfg 字段就是数据竞争，改这里则天然安全。
	noPunch atomic.Bool

	// pushed 服务端下发并已生效的配置（键名见 protocol.Cfg*）。
	pushMu sync.Mutex
	pushed map[string]string

	// hwid 本机设备标识，注册时上报，服务端据此发放 IP 租约。
	// 取不到时为空串：此时服务端按「无租约」处理（每次分配新地址），
	// 连接照常可用——设备标识只是让地址更稳定，不是连通的必要条件。
	hwid string

	// leaseUntil 本机虚拟 IP 的租约到期时刻（Unix 秒，0 表示服务端未下发）。
	leaseUntil atomic.Int64

	// rulesMu 保护 rules（服务端下发的穿透规则原始串，供界面展示）。
	//
	// 两个用途，缺一不可：
	//   - Nat 用的是解析后的 ForwardRule（虚拟端口 -> 内网目标）；
	//   - 界面要显示的是「服务端到底下发了什么」，即原始串本身。
	// 解析失败的规则不会进 Nat，但原始串仍要留着——否则用户看到的是
	// 一份「被悄悄过滤过」的列表，只会更困惑。
	rulesMu sync.Mutex
	rules   []string
}

// Rules 返回服务端下发的穿透规则原始串（副本）。
//
// 返回副本而不是内部切片：调用方（界面 / 测试）可能在别的 goroutine 里
// 遍历它，而信令循环随时会整体替换这份列表。
func (c *Client) Rules() []string {
	c.rulesMu.Lock()
	defer c.rulesMu.Unlock()
	out := make([]string, len(c.rules))
	copy(out, c.rules)
	return out
}

// setRules 保存服务端下发的穿透规则并即时生效。
//
// 服务端每次下发的都是该设备的**完整**规则集，所以这里是整体替换：
// 管理页删掉的规则必须立刻失效，合并语义会让已删除的规则永远残留。
func (c *Client) setRules(raw []string) {
	c.rulesMu.Lock()
	c.rules = append([]string(nil), raw...)
	c.rulesMu.Unlock()

	parsed, err := ParseForwards(raw)
	if err != nil {
		// 单条规则坏掉不该拖垮整批：服务端保存前已用同一套解析器校验过，
		// 走到这里意味着两边版本不一致，报一条日志比静默丢弃更容易排查。
		log.Printf("[client] 穿透规则解析失败，本批规则未生效: %v", err)
		return
	}
	nat := c.nat
	if nat == nil {
		return
	}
	nat.SetRules(parsed)
	log.Printf("[client] 已应用 %d 条穿透规则", len(parsed))
}

// NewClient 创建客户端。
func NewClient(cfg Config) *Client {
	return &Client{cfg: cfg}
}

// errNameTaken 设备名冲突（致命）：重试不可能成功，客户端直接退出。
var errNameTaken = errors.New("device name taken")

// errAuthFailed 认证失败（致命）：设备凭证与服务端不一致。
//
// 同样属于重试无意义的情况——凭证不对时重连一万次也连不上，
// 只会每 2 秒刷一行日志，把真正的原因淹没。
// （凭证被服务端清除时例外：Run 循环会清掉本地凭证自动重新注册，见 connectOnce。）
var errAuthFailed = errors.New("auth failed")

// errRegistered 注册成功标记：本次连接完成注册，需要立即用新凭证重连认证。
// 不是错误，只是让 connectOnce 提前返回、外层循环立刻重连。
var errRegistered = errors.New("registered, reconnecting")

// Run 连接服务器并进入工作循环（阻塞；断开自动重连）。
func (c *Client) Run() error {
	if c.cfg.Server == "" || c.cfg.Name == "" {
		return fmt.Errorf("server / name 不能为空")
	}
	if c.cfg.DeviceKey != "" {
		// 有凭证：数据面用服务端下发的网络密钥，信令认证用设备密钥
		devKey, err := protocol.ParseKey(c.cfg.DeviceKey)
		if err != nil {
			return fmt.Errorf("设备密钥格式错误: %w", err)
		}
		netKey, err := protocol.ParseKey(c.cfg.NetworkKey)
		if err != nil {
			return fmt.Errorf("网络密钥格式错误: %w", err)
		}
		c.crypto, err = protocol.NewCryptoWithKeys(netKey, protocol.DeviceAuthKey(devKey))
		if err != nil {
			return err
		}
	}
	// 无凭证：crypto 暂不创建，connectOnce 会先走自动注册流程拿到凭证后再重建。

	// 设备标识只取一次（每次连接都要上报，而平台查询比一次哈希贵得多）。
	// 自动注册以设备标识为身份（服务端凭 HWID 签发/复用凭证），
	// 取不到时无法注册，直接失败比无限重试更清晰。
	if c.cfg.HWID != "" {
		c.hwid = c.cfg.HWID
	} else if id, err := hwid.ID(); err != nil {
		return fmt.Errorf("无法获取本机设备标识，自动注册不可用: %w", err)
	} else {
		c.hwid = id
	}

	c.peers = make(map[uint32]*peer)
	c.punching = make(map[uint32]bool)
	c.closed = make(chan struct{})
	c.noPunch.Store(c.cfg.NoPunch)
	c.pushMu.Lock()
	c.pushed = make(map[string]string)
	c.pushMu.Unlock()

	for {
		c.session = make(chan struct{})
		c.ready = make(chan struct{})
		err := c.connectOnce()
		if err != nil {
			// 注册成功：不是错误，立即用新凭证重连认证（等一小会儿避免热循环）
			if errors.Is(err, errRegistered) {
				c.teardown()
				select {
				case <-c.closed:
					return nil
				case <-time.After(200 * time.Millisecond):
				}
				continue
			}
			// 致命错误：重试不可能成功，直接退出而不是每 2 秒重连刷屏。
			// 设备名冲突要靠对方下线才能解决，密钥不一致要靠改配置。
			if errors.Is(err, errNameTaken) || errors.Is(err, errAuthFailed) {
				return err
			}
			log.Printf("[client] 连接失败: %v，2 秒后重试", err)
			c.teardown()
			select {
			case <-c.closed:
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}
		// 会话运行中，等待断开
		select {
		case <-c.closed:
			return nil
		case <-c.session:
			log.Printf("[client] 连接断开，重连中…")
			c.teardown()
		}
	}
}

// shortDeviceID 截短设备凭证 ID 用于日志（base32 无填充 26 字符，太长）。
func shortDeviceID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

// Close 停止客户端（退出循环并清理）。
func (c *Client) Close() {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	c.endSession()
	c.teardown()
}

// endSession 标记当前会话结束（幂等）。
func (c *Client) endSession() {
	select {
	case <-c.session:
	default:
		close(c.session)
	}
}

// teardown 关闭当前会话（TUN 与网络）。
// 注意：只 Close 不置 nil——字段由 connectOnce 在每轮会话开始时重新赋值，
// 各数据循环在启动时捕获局部引用，若此处置 nil 会与仍在运行的旧循环产生数据竞争。
func (c *Client) teardown() {
	if c.tun != nil {
		c.tun.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	if c.udp != nil {
		c.udp.Close()
	}
	if c.nat != nil {
		c.nat.Close() // 停止 NAT 的连接跟踪清理协程（幂等）
	}
}

// connectOnce 单次连接生命周期：认证注册、开 TUN、三路循环。
func (c *Client) connectOnce() error {
	// 只填 IP 不填端口时默认 9000。
	srvAddr := c.cfg.Server
	if !strings.Contains(srvAddr, ":") {
		srvAddr = net.JoinHostPort(srvAddr, "9000")
	}
	conn, err := net.DialTimeout("tcp", srvAddr, 10*time.Second)
	if err != nil {
		return err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	c.conn = conn

	// 1) 认证注册：读取服务器挑战
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	m, err := protocol.ReadMsg(conn)
	if err != nil {
		return err
	}
	if m.Type != protocol.MsgChallenge || len(m.Nonce) == 0 {
		return fmt.Errorf("服务器未发起认证挑战（客户端与服务端版本不匹配？）")
	}

	// 1a) 自动注册：尚无设备凭证时，凭本机设备标识（HWID）向服务端申请长期凭证。
	// 成功拿到凭证后返回 errRegistered，外层立即重连走 Hello 认证。
	if c.cfg.DeviceKey == "" {
		if err := protocol.WriteMsg(conn, &protocol.Message{
			Type:       protocol.MsgRegister,
			DeviceName: c.cfg.Name,
			HWID:       c.hwid,
			Auth:       protocol.AuthTagFor(protocol.RegisterAuthKey(c.hwid), m.Nonce),
		}); err != nil {
			return err
		}
		m, err = protocol.ReadMsg(conn)
		if err != nil {
			return err
		}
		if m.Type != protocol.MsgRegisterOK {
			// 注册失败致命：HWID 是本机固定的，重连结果必然相同，无限重试只会刷屏。
			if m.Error == protocol.ErrAuthFailedMsg {
				return fmt.Errorf("%w：自动注册被拒绝（设备标识不可用？）", errAuthFailed)
			}
			return fmt.Errorf("%w：自动注册失败: %s", errAuthFailed, m.Error)
		}
		cred, err := protocol.DecryptCredential(c.hwid, m.Blob)
		if err != nil {
			return err
		}
		// 凭证生效：更新内存配置并重建加密器，随后持久化并重连
		devKey, err := protocol.ParseKey(cred.DeviceKey)
		if err != nil {
			return err
		}
		netKey, err := protocol.ParseKey(cred.NetworkKey)
		if err != nil {
			return err
		}
		c.cfg.DeviceID, c.cfg.DeviceKey, c.cfg.NetworkKey = cred.DeviceID, cred.DeviceKey, cred.NetworkKey
		c.crypto, err = protocol.NewCryptoWithKeys(netKey, protocol.DeviceAuthKey(devKey))
		if err != nil {
			return err
		}
		if c.cfg.OnCredential != nil {
			if err := c.cfg.OnCredential(cred.DeviceID, cred.DeviceKey, cred.NetworkKey); err != nil {
				log.Printf("[client] 凭证保存失败（本次连接不受影响，但重启后需重新注册）: %v", err)
			}
		}
		log.Printf("[client] 自动注册成功，设备凭证 %s", shortDeviceID(cred.DeviceID))
		return errRegistered
	}

	// 1b) Hello 认证：携带设备凭证（自动注册后必有）。
	hello := &protocol.Message{
		Type:       protocol.MsgHello,
		DeviceName: c.cfg.Name,
		HWID:       c.hwid,
		DeviceID:   c.cfg.DeviceID,
		Auth:       c.crypto.AuthTag(m.Nonce),
	}
	if err := protocol.WriteMsg(conn, hello); err != nil {
		return err
	}
	m, err = protocol.ReadMsg(conn)
	if err != nil {
		return err
	}
	if m.Type != protocol.MsgWelcome {
		if m.Error == protocol.ErrNameTakenMsg {
			return fmt.Errorf("%w：设备名 %q 已被占用（换个 -name，或等对方下线）", errNameTaken, c.cfg.Name)
		}
		if m.Error == protocol.ErrAuthFailedMsg {
			// 凭证被服务端清除/更换：清掉本地凭证，下次连接自动重新注册拿回原凭证
			c.cfg.DeviceID, c.cfg.DeviceKey, c.cfg.NetworkKey = "", "", ""
			c.crypto = nil
			log.Printf("[client] 设备凭证已失效，将自动重新注册…")
			return fmt.Errorf("设备凭证已失效，自动重新注册")
		}
		return fmt.Errorf("注册失败: %s", m.Error)
	}
	c.self.Store(m.VIP)
	// 租约到期时刻：只有服务端确实发了租约才记（0 表示没有）。
	// 这个值会显示在界面上，用户据此知道地址是「被保留」的，
	// 而不是这次碰巧分到的。
	//
	// 负数一律当 0 处理：老服务端曾把零值 time.Time 的 Unix()（-62135596800）
	// 原样发出来，那种值显示成「公元 1 年到期」，比不显示更糟。
	lease := m.LeaseUntil
	if lease < 0 {
		lease = 0
	}
	c.leaseUntil.Store(lease)
	// 网段由 protocol.VNetCIDR 统一约定，两端天然一致，无需在信令里协商。
	_, ipnet, err := net.ParseCIDR(protocol.VNetCIDR)
	if err != nil {
		return fmt.Errorf("cidr: %w", err)
	}
	c.net = ipnet
	log.Printf("[client] 你好 %s，你的虚拟 IP 是 %s（%s）",
		c.cfg.Name, protocol.IP4String(c.self.Load()), protocol.VNetCIDR)
	if u := c.leaseUntil.Load(); u > 0 {
		log.Printf("[client] 该地址已保留至 %s（设备标识不变则一直有效）",
			time.Unix(u, 0).Format("2006-01-02 15:04"))
	}
	// 提示本机可被访问的地址：服务监听在 0.0.0.0 时，对方用虚拟 IP 即可访问
	log.Printf("[client] 对方可通过 %s 访问本机服务（端口按实际服务端口填写）",
		protocol.IP4String(c.self.Load()))

	// 2) 数据 UDP（打洞 + 中继共用）
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	c.udp = udp
	// 只填 IP 不填端口时默认 9000。
	srvAddr = c.cfg.Server
	if !strings.Contains(srvAddr, ":") {
		srvAddr = net.JoinHostPort(srvAddr, "9000")
	}
	srvHost, srvPortStr, err := net.SplitHostPort(srvAddr)
	if err != nil {
		return err
	}
	srvIPs, err := net.LookupHost(srvHost)
	if err != nil || len(srvIPs) == 0 {
		return fmt.Errorf("解析服务器 %s 失败: %v", srvHost, err)
	}
	// 服务器 UDP 端口与 TCP 信令端口相同
	srvUDP, err := net.ResolveUDPAddr("udp", net.JoinHostPort(srvIPs[0], srvPortStr))
	if err != nil {
		return err
	}
	c.srvUDP = srvUDP

	// 3) TUN 虚拟网卡
	newTun := c.newTun
	if newTun == nil {
		newTun = func() (Tun, error) { return OpenTun("") }
	}
	tun, err := newTun()
	if err != nil {
		return err
	}
	c.tun = tun
	// 网卡配 ip/32 + 单独网段路由（见各个 tun_*.go 的 Configure 说明）：
	// 网段掩码会让内核走 ARP 而不把跨主机流量交给 TUN，导致 ping 不通。
	if err := tun.Configure(protocol.IP4String(c.self.Load())); err != nil {
		return err
	}
	log.Printf("[client] 虚拟网卡 %s 已启用，MTU 1420", tun.Name())

	// 4) NAT（内网穿透）。
	c.nat = NewNat(c.self.Load(), nil)

	// 4b) 主动查询本设备的穿透规则。
	//
	// 由客户端问、服务端答，而不是等它在注册流程里顺带推：规则按设备标识
	// 保存，「问一次答一次」的语义最直接，将来要重新同步也复用这个入口。
	// 必须放在 c.nat 建好之后——答复随时可能回来，那时 setRules 需要有
	// 一个 NAT 实例可写。
	if err := protocol.WriteMsg(conn, &protocol.Message{Type: protocol.MsgForwardGet}); err != nil {
		return err
	}

	// 5) 向服务器 UDP 注册（记录 NAT 映射候选地址）
	if err := c.sendProbeToServer(); err != nil {
		return err
	}

	// 6) 三路循环
	go c.signalingLoop()
	go c.udpLoop()
	go c.tunLoop()
	go c.heartbeatLoop()

	// 8) 已在线设备列表会通过 MsgPeerList 下发并自动发起打洞
	close(c.ready)
	return nil
}

// sendProbeToServer 用 UDP 向服务器发一个探测包，让服务器记录本机 NAT 地址。
func (c *Client) sendProbeToServer() error {
	pkt, err := c.crypto.Encrypt(protocol.FlagProbe, c.self.Load(), 0, nil)
	if err != nil {
		return err
	}
	_, err = c.udp.WriteToUDP(pkt, c.srvUDP)
	return err
}

// ---- 信令循环 ----

func (c *Client) signalingLoop() {
	defer c.endSession()
	conn := c.conn // 本会话的连接（重连后由新一轮 goroutine 捕获新引用）
	if conn == nil {
		return
	}
	for {
		conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		m, err := protocol.ReadMsg(conn)
		if err != nil {
			return
		}
		switch m.Type {
		case protocol.MsgPeerList:
			for _, p := range m.Peers {
				c.ensurePeer(p.VIP, p.Name)
				if !c.noPunch.Load() {
					c.holeRequest(conn, p.VIP)
				}
			}
		case protocol.MsgPeerOnline:
			for _, p := range m.Peers {
				c.ensurePeer(p.VIP, p.Name)
				if !c.noPunch.Load() {
					c.holeRequest(conn, p.VIP)
				}
			}
		case protocol.MsgPeerOffline:
			c.peersMu.Lock()
			delete(c.peers, m.PeerVIP)
			delete(c.punching, m.PeerVIP)
			c.peersMu.Unlock()
			log.Printf("[client] 设备 %s 下线", protocol.IP4String(m.PeerVIP))
		case protocol.MsgConfigPush:
			c.applyPushedConfig(m.Config)
		case protocol.MsgForwardPush:
			// 服务端下发的本设备穿透规则。整体替换（不是合并）：
			// 服务端给的是完整规则集，合并会让管理页删掉的规则残留。
			c.setRules(m.Rules)
		case protocol.MsgHeartbeat:
			// 收到服务端心跳回复，保持 read deadline 活跃
		case protocol.MsgHoleNotify:
			if c.noPunch.Load() {
				continue
			}
			// 服务器转告对端候选地址，开始打洞
			for _, a := range m.Addrs {
				addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(a.IP, fmt.Sprint(a.Port)))
				if err == nil {
					c.setCandidate(m.PeerVIP, addr)
					c.startPunch(m.PeerVIP)
				}
			}
		case protocol.MsgError:
			log.Printf("[client] 服务器: %s", m.Error)
			// 打洞对手尚未就绪（UDP 候选未注册）：稍后自动重试
			if m.PeerVIP != 0 && !c.noPunch.Load() && strings.Contains(m.Error, "not ready") {
				vip := m.PeerVIP
				time.AfterFunc(500*time.Millisecond, func() {
					c.peersMu.Lock()
					_, known := c.peers[vip]
					c.peersMu.Unlock()
					if known {
						c.holeRequest(conn, vip)
					}
				})
			}
		default:
			log.Printf("[client] 未知信令 %v", m.Type)
		}
	}
}

func (c *Client) ensurePeer(vip uint32, name string) *peer {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	p, ok := c.peers[vip]
	if !ok {
		p = &peer{vip: vip, name: name}
		c.peers[vip] = p
	}
	if name != "" {
		p.name = name
	}
	return p
}

// holeRequest 向服务器请求对端候选地址。
func (c *Client) holeRequest(conn net.Conn, vip uint32) {
	if conn == nil {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	protocol.WriteMsg(conn, &protocol.Message{Type: protocol.MsgHoleRequest, PeerVIP: vip})
}

func (c *Client) setCandidate(vip uint32, addr *net.UDPAddr) {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	p, ok := c.peers[vip]
	if !ok {
		p = &peer{vip: vip}
		c.peers[vip] = p
	}
	p.cand = addr
}

// startPunch 启动对某设备的打洞（去重，每个设备只有一个打洞协程）。
func (c *Client) startPunch(vip uint32) {
	c.peersMu.Lock()
	if c.punching[vip] {
		c.peersMu.Unlock()
		return
	}
	c.punching[vip] = true
	c.peersMu.Unlock()

	go func() {
		defer func() {
			c.peersMu.Lock()
			delete(c.punching, vip)
			c.peersMu.Unlock()
		}()
		for i := 0; i < 20; i++ {
			if c.isP2P(vip) {
				return
			}
			c.peersMu.Lock()
			p := c.peers[vip]
			cand := (*net.UDPAddr)(nil)
			if p != nil {
				cand = p.cand
			}
			c.peersMu.Unlock()
			if cand == nil {
				return
			}
			pkt, err := c.crypto.Encrypt(protocol.FlagProbe, c.self.Load(), vip, nil)
			if err == nil {
				c.udp.WriteToUDP(pkt, cand)
			}
			time.Sleep(200 * time.Millisecond)
		}
		log.Printf("[client] 与 %s 打洞未成功，将走服务器中转", protocol.IP4String(vip))
	}()
}

func (c *Client) isP2P(vip uint32) bool {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	p, ok := c.peers[vip]
	return ok && p.p2p
}

func (c *Client) setP2P(vip uint32, addr *net.UDPAddr) {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	p, ok := c.peers[vip]
	if !ok {
		p = &peer{vip: vip}
		c.peers[vip] = p
	}
	if addr != nil {
		p.addr = addr
	}
	if !p.p2p {
		p.p2p = true
		log.Printf("[client] ✓ 与 %s(%s) P2P 直连成功（%s）",
			protocol.IP4String(vip), p.name, addr)
	}
}

// ---- UDP 数据循环 ----

func (c *Client) udpLoop() {
	defer c.endSession()
	// 局部引用，避免 teardown 置空字段后访问竞态
	udp := c.udp
	tun := c.tun
	nat := c.nat
	srvUDP := c.srvUDP
	buf := make([]byte, protocol.MaxPacket)
	for {
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt, err := c.crypto.Decrypt(buf[:n])
		if err != nil {
			continue
		}
		// 来源是服务器中继的包不构成 P2P 证据：
		// 只有数据/探测确实直达本机 UDP 地址时才判定直连成功，
		// 否则打洞失败的中继流量会被误报为"P2P 直连成功"。
		isRelay := sameUDPAddr(from, srvUDP)
		switch pkt.Flags & 0xF0 {
		case protocol.FlagProbe:
			// 对端打洞探测：记录其真实地址，回复确认（忽略服务器回弹的自身包）
			if pkt.Source != c.self.Load() && !isRelay {
				c.setP2P(pkt.Source, from)
				rep, err := c.crypto.Encrypt(protocol.FlagReply, c.self.Load(), pkt.Source, nil)
				if err == nil {
					udp.WriteToUDP(rep, from)
				}
			}
		case protocol.FlagReply:
			// 打洞成功
			if pkt.Source != c.self.Load() && !isRelay {
				c.setP2P(pkt.Source, from)
			}
		case protocol.FlagData:
			// 对端已直接发数据 → 通路确认（中继来源除外）
			if pkt.Source != c.self.Load() && !isRelay {
				c.setP2P(pkt.Source, from)
			}
			if pkt.Source == c.self.Load() {
				continue // 自己发出的包（服务端回弹等），不重复交付
			}
			switch {
			case pkt.Dest == c.self.Load():
				// 命中穿透规则则 DNAT 后写回 TUN（内核路由到内网），否则直接交付本机
				if nat != nil {
					nat.DNAT(pkt.Data)
				}
				tun.Write(pkt.Data)
			case pkt.Dest == protocol.VNetBroadcast:
				if rewriteDstToSelf(pkt.Data, c.self.Load()) {
					tun.Write(pkt.Data)
				}
			}
		}
	}
}

// sameUDPAddr 比较两个 UDP 地址是否相同（IP + 端口）。
func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

// ---- TUN 数据循环 ----

func (c *Client) tunLoop() {
	defer c.endSession()
	tun := c.tun // 局部引用，避免 teardown 竞态
	netC := c.net
	nat := c.nat
	buf := make([]byte, 2048)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		// 只处理 IPv4
		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			continue
		}
		dst := binary.BigEndian.Uint32(pkt[16:20])
		if !netC.Contains(net.IP(pkt[16:20])) {
			continue // 不是虚拟网段，不劫持
		}
		// 内网穿透回包 SNAT（源为内网目标地址）
		if nat != nil {
			nat.SNAT(pkt)
		}
		// 封装并发往对端（P2P 优先，否则中继）
		enc, err := c.crypto.Encrypt(protocol.FlagData, c.self.Load(), dst, pkt)
		if err != nil {
			continue
		}
		c.sendEnc(enc, dst)
	}
}

// sendEnc 发送封装包：P2P 直连优先，否则走服务器中继。
// udp/srvUDP 用局部引用，避免 teardown 竞态。
func (c *Client) sendEnc(enc []byte, dstVIP uint32) {
	udp := c.udp
	srvUDP := c.srvUDP
	if udp == nil || srvUDP == nil {
		return
	}
	c.peersMu.Lock()
	p := c.peers[dstVIP]
	var addr *net.UDPAddr
	if p != nil && p.p2p && p.addr != nil {
		addr = p.addr
	}
	c.peersMu.Unlock()
	if addr != nil {
		udp.WriteToUDP(enc, addr)
	} else {
		udp.WriteToUDP(enc, srvUDP)
	}
}

// ---- 心跳 ----

func (c *Client) heartbeatLoop() {
	conn := c.conn // 本会话连接，重连后由新 goroutine 重新捕获
	session := c.session
	if conn == nil || session == nil {
		return
	}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-session: // 会话结束：退出，避免 goroutine 泄漏
			return
		case <-t.C:
			c.writeMu.Lock()
			err := protocol.WriteMsg(conn, &protocol.Message{Type: protocol.MsgHeartbeat})
			c.writeMu.Unlock()
			if err != nil {
				return // 连接已失效（会话随后也会结束）
			}
		}
	}
}

// ---- 状态查询（供 GUI 轮询）----

// SelfVIP 返回本机虚拟 IP（网络字节序）；未注册完成时返回 0。
func (c *Client) SelfVIP() uint32 { return c.self.Load() }

// PeerStats 返回 (已打洞直连的对端数, 已知对端总数)。
// 用于界面区分「直连」与「中转」。
func (c *Client) PeerStats() (direct, total int) {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	for _, p := range c.peers {
		total++
		if p.p2p {
			direct++
		}
	}
	return direct, total
}

// ParseForwards 解析多条内网穿透规则。
//
// 实现放在 internal/forward：服务端下发穿透规则前要用同一份解析器做校验，
// 两边各写一套迟早会漂移成「服务端认为合法、客户端解析失败」。
func ParseForwards(list []string) ([]ForwardRule, error) {
	return forward.ParseList(list)
}

// ParseForwardRule 解析单条规则（"虚拟端口=内网目标IP:端口"）。
func ParseForwardRule(s string) (ForwardRule, error) {
	return forward.Parse(s)
}

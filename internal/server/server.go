package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sulink-lan/internal/protocol"
)

// Config 服务器配置。
type Config struct {
	TCPAddr string // 信令监听地址，如 0.0.0.0:9000
	UDPAddr string // 中继监听地址，如 0.0.0.0:9000
	// LeaseFile 设备表（IP 租约 + 设备凭证 + 每台设备的穿透规则）的落盘路径；
	// 留空表示只在内存中保存（测试用，重启即丢）。
	LeaseFile string
	// ConfigFile 全局配置（公告 / 禁止打洞）的落盘路径；留空同上。
	ConfigFile string
}

// Device 一台在线客户端。
type Device struct {
	Name string
	VIP  uint32 // 虚拟 IP（网络字节序）
	// HWID 设备稳定标识（老客户端为空串）。IP 租约与穿透规则都以它为主键；
	// 为空时该设备退化为「每次上线分配新地址、不接收穿透规则」。
	HWID     string
	Conn     net.Conn
	UDPAddr  *net.UDPAddr // 客户端 UDP 候选地址（打洞/中继用）
	OnlineAt time.Time
	mu       sync.Mutex             // 保护 msgCh 的发送与关闭互斥
	msgCh    chan *protocol.Message // 串行化写队列（writer goroutine 消费）
}

// sendMsg 向设备发送一条信令消息（非阻塞投递到写队列，由专用 goroutine 串行写出，
// 避免多个 goroutine 并发写 TCP 损坏消息，也避免写锁交叉死锁）。
func (s *Server) sendMsg(dev *Device, m *protocol.Message) {
	if dev == nil || dev.Conn == nil {
		return
	}
	dev.mu.Lock()
	defer dev.mu.Unlock()
	if dev.msgCh == nil {
		return
	}
	select {
	case dev.msgCh <- m:
	default:
		// 写队列满（连接异常），丢弃
	}
}

// closeMsg 关闭设备的写队列（与 sendMsg 互斥，防止 close 与发送竞争）。
func (d *Device) closeMsg() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.msgCh != nil {
		close(d.msgCh)
		d.msgCh = nil
	}
}

// writeLoop 设备的信令写协程：串行写出队列中的消息。
func (d *Device) writeLoop() {
	d.mu.Lock()
	ch := d.msgCh
	d.mu.Unlock()
	if ch == nil {
		return
	}
	for m := range ch {
		if err := protocol.WriteMsg(d.Conn, m); err != nil {
			return
		}
	}
}

// Server 主结构。
type Server struct {
	cfg      Config
	relayCrypto *protocol.Crypto // 中继校验/合成应答用的数据面密钥
	// networkKey 数据面共享密钥：设备在注册响应里加密收到，此后数据面
	// 统一用它加解密（与客户端 cert 数据密钥一致）。持久化于 network.key。
	networkKey []byte
	ipPool     *IPPool
	mu         sync.Mutex
	devices    map[uint32]*Device // VIP -> device
	byID       map[string]*Device // 设备名 -> device（防重名）
	addrMu     sync.Mutex
	tcpAddr    string    // 实际监听地址（端口填 0 时供外部获取）
	udpAddr    string    // 中继 UDP 实际监听地址（管理页展示用）
	started    time.Time // 启动时刻（管理页展示运行时长）

	// deviceTable 设备表：IP 租约 + 每台设备的穿透规则，按设备标识索引，落盘保存。
	deviceTable *DeviceTable

	// 中继热路径的统计计数。用原子变量而非互斥锁：
	// 这些数字每收一个包就要加一次，为它们加锁会把整条转发路径串行化。
	statPkts     atomic.Uint64 // 成功转发的数据包数
	statBytes    atomic.Uint64 // 成功转发的字节数
	statFlooded  atomic.Uint64 // 泛洪转发次数（每收一个广播包计一次）
	statICMP     atomic.Uint64 // 合成的 ICMP 应答数
	statRejected atomic.Uint64 // 认证失败被丢弃的包数

	// 管理页下发过的全局配置（公告 / 禁止打洞），落盘到 cfg.ConfigFile。
	//
	// 与「只存内存」的早期实现相比，落盘是为了兑现一个承诺：
	// 公告发出去之后，哪怕服务端重启，新上线的设备也必须还能看到它。
	// 只存内存时重启一次公告就凭空消失，且没有任何提示。
	pushMu       sync.Mutex
	pushed       map[string]string
	settingsPath string

	// closeCh 关闭信号，用于优雅退出。
	closeCh   chan struct{}
	closeOnce sync.Once

	// OnDeviceOnline 设备上线回调（可选）：设备完成认证并拿到虚拟 IP 后调用。
	// vkey 是该设备的长期凭证密钥（device_key），供嵌入组件（如 NPS NPC 自动注册）使用。
	OnDeviceOnline func(vkey, name, vip string)
}

// New 创建服务器。
//
// 认证模型：无预共享密钥、无注册码。客户端打开软件时凭本机设备标识
// （HWID）自动注册，服务端为每台设备签发/复用长期凭证（见 handleRegister），
// 此后连接用设备凭证做 HMAC 挑战应答认证。数据面统一用服务端生成的
// 网络密钥（network.key）加解密。
func New(cfg Config) (*Server, error) {
	pool, err := NewIPPool()
	if err != nil {
		return nil, err
	}
	// 网络密钥与设备表同目录落盘：状态文件一处管理，备份与迁移只需拷贝一个目录。
	netKeyPath := ""
	if cfg.LeaseFile != "" {
		netKeyPath = filepath.Join(filepath.Dir(cfg.LeaseFile), "network.key")
	}
	netKey, err := loadOrCreateNetworkKey(netKeyPath)
	if err != nil {
		return nil, err
	}
	relayCrypto, err := protocol.NewCryptoWithKeys(netKey, netKey)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:          cfg,
		relayCrypto:  relayCrypto,
		networkKey:   netKey,
		ipPool:       pool,
		devices:      make(map[uint32]*Device),
		byID:         make(map[string]*Device),
		deviceTable:  NewDeviceTable(cfg.LeaseFile),
		settingsPath: cfg.ConfigFile,
		pushed:       loadSettings(cfg.ConfigFile),
		started:      time.Now(),
	}, nil
}

// Addr 返回实际信令监听地址（Run 之前为空字符串）。
func (s *Server) Addr() string {
	s.addrMu.Lock()
	defer s.addrMu.Unlock()
	return s.tcpAddr
}

// loadOrCreateNetworkKey 加载或生成数据面网络密钥（32 字节，hex 落盘 0600）。
// path 为空时只在内存生成（测试用，重启即换——对测试无影响，因为
// 注册与认证在同一进程内完成）。
func loadOrCreateNetworkKey(path string) ([]byte, error) {
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if key, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil && len(key) == 32 {
				return key, nil
			}
			log.Printf("[server] 网络密钥文件损坏，重新生成 %s", path)
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if path != "" {
		if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
			return nil, fmt.Errorf("网络密钥写入失败: %w", err)
		}
	}
	return key, nil
}

// Run 启动信令 TCP 监听和 UDP 中继，阻塞直到 ctx 取消。
// TCPAddr/UDPAddr 端口可填 0：此时 TCP 随机分配端口，UDP 复用同一端口。
func (s *Server) Run(ctx context.Context) error {
	tcpLn, err := net.Listen("tcp", s.cfg.TCPAddr)
	if err != nil {
		return err
	}
	defer tcpLn.Close()
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port
	s.addrMu.Lock()
	s.tcpAddr = tcpLn.Addr().String()
	s.addrMu.Unlock()

	udpListen := s.cfg.UDPAddr
	if _, p, err := net.SplitHostPort(udpListen); err == nil && p == "0" {
		host, _, _ := net.SplitHostPort(udpListen)
		if host == "" {
			host = "0.0.0.0"
		}
		udpListen = net.JoinHostPort(host, fmt.Sprint(tcpPort))
	}
	udpConn, err := net.ListenPacket("udp", udpListen)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	s.addrMu.Lock()
	s.udpAddr = udpConn.LocalAddr().String()
	s.addrMu.Unlock()
	s.closeCh = make(chan struct{})

	log.Printf("[server] 信令 TCP 监听 %s", tcpLn.Addr())
	log.Printf("[server] 中继 UDP 监听 %s", udpConn.LocalAddr())
	log.Printf("[server] 虚拟网段 %s，服务器虚拟 IP %s",
		protocol.VNetCIDR, protocol.IP4String(s.ipPool.ServerVIP()))
	// 把两份状态文件的绝对路径打出来：它们决定了「重启后租约与公告还在不在」，
	// 运维部署到 systemd / 容器时，工作目录与预期不符是最常见的一类问题。
	// 路径为空表示只在内存中（测试或显式关闭持久化），此时打印 absPath("")
	// 会得到当前工作目录——一个看起来像配置正确、实际什么都没存的路径，
	// 比不打更糟，所以这种情况明确说清楚。
	log.Printf("[server] 设备表文件 %s", filePathOrDisabled(s.cfg.LeaseFile))
	log.Printf("[server] 全局配置文件 %s", filePathOrDisabled(s.cfg.ConfigFile))

	go s.acceptLoop(tcpLn)
	go s.relayLoop(udpConn.(*net.UDPConn))
	go s.leaseSweeper(ctx)

	<-ctx.Done()
	return nil
}

// leaseSweeper 定期回收过期租约。
//
// 分配地址时也会顺手回收（见 DeviceTable.Assign），但那只在「恰好有设备要
// 上线」时发生。若服务端长期没有新设备，过期地址就会一直占着池子，
// 直到某个新设备上线才被释放——池子里的可用地址数因此长期偏低。
// 这个定时任务保证回收不依赖外部事件。
func (s *Server) leaseSweeper(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := s.deviceTable.Prune(time.Now(), s.ipPool); n > 0 {
				log.Printf("[server] 已回收 %d 个到期地址", n)
			}
		}
	}
}

// acceptLoop 接受信令 TCP 连接。
func (s *Server) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

// rejectAuth 认证失败：停止写队列后同步写出错误再退出，
// 确保客户端能收到失败原因（异步队列来不及消费连接就会被关闭）。
func rejectAuth(dev *Device, reason string) {
	dev.closeMsg()
	protocol.WriteMsg(dev.Conn, &protocol.Message{Type: protocol.MsgError, Error: reason})
}

// handleRegister 处理自动注册请求：
// 校验 HWID 挑战应答 -> 为该设备签发（或复用）设备凭证 -> 加密下发
// （含数据面网络密钥）。成功后连接即关闭，客户端用新凭证重连认证——
// 注册与认证分离，复用了既有的 Hello 认证路径。
//
// 信任模型：HWID 是本机硬件标识（可被读取/复制），不是秘密。因此
// 「见 HWID 即注册」意味着——能连到服务端地址的设备即可入网，设备
// 身份与硬件绑定；换台机器（不同 HWID）不会继承原设备的凭证与租约。
// 已注册设备重连时**复用原凭证**而非换新：重装系统 / 误删配置后，
// 客户端打开软件即可自动找回身份，无需管理员介入。
func (s *Server) handleRegister(dev *Device, m *protocol.Message, challenge []byte) {
	hwid := strings.TrimSpace(m.HWID)
	if hwid == "" {
		// 凭证与设备标识绑定：没有稳定标识就无法定位这台设备的租约与规则，
		// 注册出来的凭证也用不上，直接拒绝比发一张废凭证好。
		log.Printf("[server] 拒绝注册（来自 %s）：未携带设备标识，无法注册", dev.Conn.RemoteAddr())
		rejectAuth(dev, "device id required")
		return
	}
	if !protocol.VerifyRegisterAuth(hwid, challenge, m.Auth) {
		log.Printf("[server] 拒绝注册（设备 %s）：设备标识认证失败", shortHWID(hwid))
		rejectAuth(dev, protocol.ErrAuthFailedMsg)
		return
	}
	// 封禁闸门：管理员「清除凭证/踢下线」把设备置为封禁后，
	// 不允许它再凭 HWID 自动注册回来。
	if s.deviceTable.IsBlocked(hwid) {
		log.Printf("[server] 拒绝注册（设备 %s）：已被管理员封禁", shortHWID(hwid))
		rejectAuth(dev, "device blocked by administrator")
		return
	}
	// 已有凭证则复用（重装/重连自愈），没有则签发新凭证。
	deviceID, deviceKey, ok := s.deviceTable.Credential(hwid)
	if !ok {
		var err error
		deviceID, err = protocol.GenerateDeviceID()
		if err != nil {
			log.Printf("[server] 注册失败：生成设备凭证失败: %v", err)
			rejectAuth(dev, "internal error")
			return
		}
		deviceKey, err = protocol.GenerateKey()
		if err != nil {
			log.Printf("[server] 注册失败：生成设备密钥失败: %v", err)
			rejectAuth(dev, "internal error")
			return
		}
		if err := s.deviceTable.SetCredential(hwid, m.DeviceName, deviceID, deviceKey); err != nil {
			// 并发注册竞争：另一连接刚写入了凭证，回查一次直接用它的。
			if deviceID2, deviceKey2, ok2 := s.deviceTable.Credential(hwid); ok2 {
				deviceID, deviceKey = deviceID2, deviceKey2
			} else {
				log.Printf("[server] 拒绝注册（设备 %s）：%v", shortHWID(hwid), err)
				rejectAuth(dev, "device already registered")
				return
			}
		}
	}
	blob, err := protocol.EncryptCredential(hwid, &protocol.Credential{
		DeviceID:   deviceID,
		DeviceKey:  deviceKey,
		NetworkKey: hex.EncodeToString(s.networkKey),
	})
	if err != nil {
		log.Printf("[server] 注册失败：加密凭证失败: %v", err)
		rejectAuth(dev, "internal error")
		return
	}
	// 与 rejectAuth 同模式：challenge 已由写协程写完，这里同步写出后关连接
	dev.closeMsg()
	if err := protocol.WriteMsg(dev.Conn, &protocol.Message{Type: protocol.MsgRegisterOK, Blob: blob}); err != nil {
		log.Printf("[server] 注册响应发送失败: %v", err)
		return
	}
	log.Printf("[server] 设备 %s（%s）自动注册成功，凭证 %s%s",
		m.DeviceName, shortHWID(hwid), shortID(deviceID),
		map[bool]string{true: "（复用原凭证）", false: ""}[ok])
}

// shortID 截短设备凭证 ID 用于日志（base32 无填充 26 字符，太长）。
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

// handleConn 处理一个客户端信令连接。
func (s *Server) handleConn(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	dev := &Device{Conn: conn, OnlineAt: time.Now(), msgCh: make(chan *protocol.Message, 64)}
	go dev.writeLoop()
	defer func() {
		conn.Close()
		dev.closeMsg()
		s.removeDevice(dev)
	}()

	// 0) 认证挑战：下发随机 nonce，要求后续消息携带正确 HMAC 标签，
	//    未持有设备凭证的连接无法上线（防枚举设备 / 耗尽 IP 池 / 垃圾信令）。
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		return
	}
	s.sendMsg(dev, &protocol.Message{Type: protocol.MsgChallenge, Nonce: challenge})

	// 首条消息分流：
	//	- MsgRegister：自动注册（按设备标识 HWID），成功后连接即关，
	//	  客户端用新凭证重连认证；
	//	- MsgHello：设备凭证认证。
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	m, err := protocol.ReadMsg(conn)
	if err != nil {
		log.Printf("[server] 读认证消息失败: %v", err)
		return
	}
	switch m.Type {
	case protocol.MsgRegister:
		s.handleRegister(dev, m, challenge)
		return
	case protocol.MsgHello:
		// 继续下面的认证
	default:
		log.Printf("[server] 拒绝连接（来自 %s）：首条信令不是 Hello/Register（type=%d），可能是端口扫描或版本不匹配",
			conn.RemoteAddr(), m.Type)
		rejectAuth(dev, "protocol error: expected hello or register")
		return
	}
	if m.DeviceName == "" {
		log.Printf("[server] 拒绝连接（来自 %s）：Hello 未携带设备名", conn.RemoteAddr())
		rejectAuth(dev, "device name required")
		return
	}
	// 认证：仅设备凭证。自动注册后每台设备都持有服务端签发的凭证，
	// Hello 必须携带 DeviceID 并给出正确的挑战应答。
	if m.DeviceID == "" {
		log.Printf("[server] 拒绝连接（设备 %q 来自 %s）：未携带设备凭证（请使用新版客户端，打开软件自动注册）",
			m.DeviceName, conn.RemoteAddr())
		rejectAuth(dev, protocol.ErrAuthFailedMsg)
		return
	}
	key := s.deviceTable.DeviceKeyByID(m.DeviceID)
	if key == "" {
		log.Printf("[server] 拒绝连接（设备 %q）：设备凭证 %s 未注册或已被清除",
			m.DeviceName, shortID(m.DeviceID))
		rejectAuth(dev, protocol.ErrAuthFailedMsg)
		return
	}
	if !protocol.VerifyDeviceAuth(key, challenge, m.Auth) {
		log.Printf("[server] 拒绝连接（设备 %q 凭证 %s）：认证失败，设备密钥不匹配",
			m.DeviceName, shortID(m.DeviceID))
		rejectAuth(dev, protocol.ErrAuthFailedMsg)
		return
	}

	vip, leaseUntil, err := s.register(dev, m.DeviceName, m.HWID)
	if err != nil {
		rejectAuth(dev, err.Error())
		return
	}
	if m.HWID == "" {
		// 老客户端不带设备标识：地址每次上线都可能变，也没有穿透规则可下发。
		// 明确记一行，免得日后有人对着日志疑惑「为什么这台设备没有租约」。
		log.Printf("[server] %s 上线，虚拟 IP %s（未携带设备标识，不分配租约）",
			m.DeviceName, protocol.IP4String(vip))
	} else {
		log.Printf("[server] %s 上线，虚拟 IP %s，设备 %s，租约至 %s",
			m.DeviceName, protocol.IP4String(vip), shortHWID(m.HWID),
			leaseUntil.Format("2006-01-02 15:04"))
		// 通知嵌入组件（NPS NPC 自动注册等）
		if s.OnDeviceOnline != nil && m.DeviceID != "" {
			dk := s.deviceTable.DeviceKeyByID(m.DeviceID)
			if dk != "" {
				go s.OnDeviceOnline(dk, m.DeviceName, protocol.IP4String(vip))
			}
		}
	}

	// Welcome
	//
	// 租约到期时刻只在真的有租约时才填：零值 time.Time 的 Unix() 是
	// -62135596800，一个「看起来像数字」的负数。若原样下发，客户端会把它
	// 当成有效租约存下来，界面上显示成公元 1 年的到期时间——比不显示更糟。
	// 0 在协议里明确表示「无租约」。
	var leaseUnix int64
	if !leaseUntil.IsZero() {
		leaseUnix = leaseUntil.Unix()
	}
	welcome := &protocol.Message{
		Type: protocol.MsgWelcome,
		VIP:  vip,
		// 租约到期时刻一并下发：客户端把它显示成「地址保留至 X」，
		// 用户因此知道地址是「被保留」的，而不是碰巧分到的。
		LeaseUntil: leaseUnix,
	}

	s.sendMsg(dev, welcome)

	// 在线设备列表
	peers := s.peerList(vip)
	s.sendMsg(dev, &protocol.Message{Type: protocol.MsgPeerList, Peers: peers})

	// 补发当前生效的下发配置。
	// 管理页下发过的策略必须对「之后才上线的设备」同样有效，
	// 否则管理员每新增一台设备都要记得重新点一次「下发」——迟早会忘。
	if cfg := s.PushedConfig(); len(cfg) > 0 {
		s.sendMsg(dev, &protocol.Message{Type: protocol.MsgConfigPush, Config: cfg})
	}

	// 广播上线
	s.notifyOnline(dev)

	// 信令循环
	conn.SetReadDeadline(time.Time{})
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		m, err := protocol.ReadMsg(conn)
		if err != nil {
			log.Printf("[server] %s 断开: %v", dev.Name, err)
			return
		}
		switch m.Type {
		case protocol.MsgHeartbeat:
			// 保活：原样回一个心跳，让客户端的 read deadline 不会触发。
			// 心跳本来是单向的，但客户端 signalingLoop 有 70 秒读超时；
			// 单设备且无消息交换时，客户端 70 秒内收不到任何消息会主动断开。
			s.sendMsg(dev, &protocol.Message{Type: protocol.MsgHeartbeat})
		case protocol.MsgHoleRequest:
			s.handleHoleRequest(dev, m.PeerVIP)
		case protocol.MsgForwardGet:
			// 客户端查询本设备的穿透规则。由客户端主动问、服务端答，
			// 而不是服务端在注册流程里顺带推：规则按设备标识保存，
			// 「问一次答一次」语义更直接，将来要重新同步也复用这个入口。
			s.sendMsg(dev, &protocol.Message{
				Type:  protocol.MsgForwardPush,
				Rules: s.deviceTable.Forward(dev.HWID),
			})
		default:
			log.Printf("[server] %s 未知消息类型 %v", protocol.IP4String(vip), m.Type)
		}
	}
}

// register 注册设备并分配虚拟 IP，返回地址与租约到期时刻。
// dev 必须已带 conn 与写队列（见 handleConn）。
//
// 顺序上先分配地址、再登记设备表：分配可能触发设备表落盘（毫秒级磁盘写），
// 而登记要持有 s.mu。若把落盘放在 s.mu 里，一次磁盘写入就会把整张
// 设备表（注册/下线/心跳）一起堵住。代价是名字冲突要回滚刚分配的地址。
func (s *Server) register(dev *Device, name, hwid string) (uint32, time.Time, error) {
	vip, leaseUntil, err := s.allocVIP(hwid, name)
	if err != nil {
		return 0, time.Time{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 重名处理：设备名只是显示用，真正的唯一标识是 HWID。
	// 两台机器同名（克隆镜像、OEM 默认名相同）很常见，直接拒绝会让
	// 第二台秒断秒连。这里改成自动改名：被占了就加个序号后缀。
	if old, dup := s.byID[name]; dup && old != dev {
		base := name
		for i := 2; ; i++ {
			cand := fmt.Sprintf("%s (%d)", base, i)
			if _, taken := s.byID[cand]; !taken {
				name = cand
				break
			}
		}
	}

	// 同一设备标识的新连接接管旧连接：同一台机器上跑了两个实例，
	// 或设备重启后旧连接还没超时。让新连接胜出（与 DHCP 的「后来者续约」一致），
	// 否则两个实例会顶着同一个虚拟地址收发，数据包互相串台。
	if old := s.devices[vip]; old != nil && old != dev {
		log.Printf("[server] %s(%s) 已有连接在网，新连接接管，断开旧连接",
			name, protocol.IP4String(vip))
		old.Conn.Close()
	}

	dev.Name, dev.VIP, dev.HWID = name, vip, hwid
	s.devices[vip] = dev
	s.byID[name] = dev
	return vip, leaseUntil, nil
}

// allocVIP 取地址：有设备标识走租约表（尽量给回原地址），没有则从池子里新分配。
func (s *Server) allocVIP(hwid, name string) (uint32, time.Time, error) {
	if hwid == "" {
		// 防御分支：自动注册后所有设备都带 HWID，理论上到不了这里；
		// 留空时退化为「每次上线分配新地址」，不建立租约，也不绑定凭证。
		vip, err := s.ipPool.Alloc()
		return vip, time.Time{}, err
	}
	return s.deviceTable.Assign(hwid, name, s.ipPool, time.Now())
}

// removeDevice 下线：关闭连接、广播、按租约规则决定是否回收地址。
func (s *Server) removeDevice(dev *Device) {
	if dev == nil {
		return
	}
	s.mu.Lock()
	if cur, ok := s.devices[dev.VIP]; ok && cur == dev {
		delete(s.devices, dev.VIP)
	}
	if cur, ok := s.byID[dev.Name]; ok && cur == dev {
		delete(s.byID, dev.Name)
	}
	// 地址是否归还，取决于它有没有被租约占用：
	//   - 有设备标识 → 地址留在租约表里，不归还。否则「同一台设备每次
	//     拿回同一个地址」这个承诺在设备重连时就断了——而重连恰恰是常态。
	//   - 无设备标识 → 沿用旧行为立即归还。
	// 另外，若该地址已被新设备接管（s.devices[vip] 换人），绝不能归还：
	// 那会把别人正在用的地址从池子里放出去，第三个设备可能再拿到同一个地址。
	_, takenOver := s.devices[dev.VIP]
	release := dev.VIP != 0 && dev.HWID == "" && !takenOver
	s.mu.Unlock()
	if release {
		s.ipPool.Release(dev.VIP)
	}
	if dev.VIP == 0 {
		return // 未完成注册的连接，无需广播
	}
	log.Printf("[server] %s (%s) 下线", dev.Name, protocol.IP4String(dev.VIP))
	s.notifyOffline(dev.VIP)
}

// handleHoleRequest 协助打洞：把双方 UDP 候选地址互发。
func (s *Server) handleHoleRequest(from *Device, peerVIP uint32) {
	s.mu.Lock()
	peer := s.devices[peerVIP]
	fromAddr := from.UDPAddr
	peerAddr := (*net.UDPAddr)(nil)
	if peer != nil {
		peerAddr = peer.UDPAddr
	}
	s.mu.Unlock()

	if peer == nil || peerAddr == nil {
		// 对端不在线或尚无 UDP 候选
		s.sendMsg(from, &protocol.Message{Type: protocol.MsgError, Error: "peer not ready", PeerVIP: peerVIP})
		return
	}
	// 告诉 from：peer 的候选地址
	s.sendMsg(from, &protocol.Message{
		Type:    protocol.MsgHoleNotify,
		PeerVIP: peerVIP,
		Addrs:   []protocol.Addr{{IP: peerAddr.IP.String(), Port: peerAddr.Port}},
	})
	// 告诉 peer：from 的候选地址
	if fromAddr != nil {
		s.sendMsg(peer, &protocol.Message{
			Type:    protocol.MsgHoleNotify,
			PeerVIP: from.VIP,
			Addrs:   []protocol.Addr{{IP: fromAddr.IP.String(), Port: fromAddr.Port}},
		})
	}
}

// peerList 返回除 self 外的在线设备。
func (s *Server) peerList(self uint32) []protocol.Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []protocol.Peer
	for vip, d := range s.devices {
		if vip == self {
			continue
		}
		out = append(out, protocol.Peer{Name: d.Name, VIP: vip})
	}
	return out
}

// notifyOnline 广播设备上线。
func (s *Server) notifyOnline(dev *Device) {
	s.mu.Lock()
	devices := make([]*Device, 0, len(s.devices))
	for _, d := range s.devices {
		if d != dev {
			devices = append(devices, d)
		}
	}
	s.mu.Unlock()
	for _, d := range devices {
		s.sendMsg(d, &protocol.Message{Type: protocol.MsgPeerOnline, Peers: []protocol.Peer{{Name: dev.Name, VIP: dev.VIP}}})
	}
}

// notifyOffline 广播设备下线。
func (s *Server) notifyOffline(vip uint32) {
	s.mu.Lock()
	devices := make([]*Device, 0, len(s.devices))
	for _, d := range s.devices {
		devices = append(devices, d)
	}
	s.mu.Unlock()
	for _, d := range devices {
		s.sendMsg(d, &protocol.Message{Type: protocol.MsgPeerOffline, PeerVIP: vip})
	}
}

// relayLoop UDP 中继：按数据包头部的目标虚拟 IP 转发。
// 每个包先经 AES-GCM 解密验证（服务器持有数据面网络密钥）：无法通过认证的包
// 一律丢弃——伪造 src VIP 的明文包既不能触发转发，也不能污染设备的
// UDPAddr 记录。验证通过后转发原始密文（零额外加密开销）。
func (s *Server) relayLoop(conn *net.UDPConn) {
	buf := make([]byte, protocol.MaxPacket)
	serverVIP := s.ipPool.ServerVIP()
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < protocol.HeaderLen {
			continue
		}
		pkt, err := s.relayCrypto.Decrypt(buf[:n])
		if err != nil {
			s.statRejected.Add(1)
			continue // 无法认证：伪造或损坏的包，直接丢弃
		}
		flags := pkt.Flags
		srcVIP := pkt.Source
		dstVIP := pkt.Dest

		s.mu.Lock()
		srcDev := s.devices[srcVIP]
		dstDev := s.devices[dstVIP]
		// 记录/刷新 UDP 候选地址（每次都更新：客户端 NAT 映射变化后自动修正）
		if srcDev != nil {
			srcDev.UDPAddr = addr
		}
		s.mu.Unlock()

		// 打洞探测包：只要来自已注册设备就按目标 VIP 转发（帮助穿透双方 NAT）
		if flags&0xF0 == protocol.FlagProbe || flags&0xF0 == protocol.FlagReply {
			if srcDev == nil {
				continue
			}
			if dstDev != nil && dstDev.UDPAddr != nil {
				conn.WriteToUDP(buf[:n], dstDev.UDPAddr)
			} else {
				// 目标未知时原路弹回，用于双向确认
				conn.WriteToUDP(buf[:n], addr)
			}
			continue
		}

		// 数据包发往服务器自身的虚拟 IP：服务端是纯用户态进程，没有 TUN，
		// 不会有内核替 10.0.0.1 应答。这里合成 ICMP echo 应答，
		// 让 `ping 10.0.0.1` 成为可用的连通性自检点（详见 icmp.go）。
		if flags&0xF0 == protocol.FlagData && dstVIP == serverVIP {
			if srcDev == nil {
				continue // 未注册设备不得触发应答
			}
			if reply, ok := echoReply(pkt.Data, serverVIP); ok {
				if enc, err := s.relayCrypto.Encrypt(protocol.FlagData, serverVIP, srcVIP, reply); err == nil {
					// 回给包的实际来处：这正是该设备最新的 NAT 映射地址
					conn.WriteToUDP(enc, addr)
					s.statICMP.Add(1)
				}
			}
			continue
		}

		// 定向广播（10.255.255.255）：泛洪给所有在线设备。
		//
		// 三层隧道只转发单播：广播包按目标 VIP 查表必然落空而被丢弃，
		// 表现为「虚拟局域网内互相发现不了」。这里显式泛洪，让依赖
		// 网段广播的应用（局域网发现类协议）能够工作。
		// 注意泛洪的是原始密文，服务端不额外加解密，也不回给发送者本人。
		if flags&0xF0 == protocol.FlagData && dstVIP == protocol.VNetBroadcast {
			if srcDev == nil {
				continue // 未注册设备不得触发泛洪
			}
			s.flood(conn, buf[:n], srcVIP)
			s.statFlooded.Add(1)
			continue
		}

		// 数据包：转发给目标设备
		if srcDev == nil || dstDev == nil || dstDev.UDPAddr == nil {
			continue
		}
		if _, err := conn.WriteToUDP(buf[:n], dstDev.UDPAddr); err != nil {
			log.Printf("[server] 中继转发失败: %v", err)
			continue
		}
		s.statPkts.Add(1)
		s.statBytes.Add(uint64(n))
	}
}

// flood 把密文原样转发给除发送者外的所有在线设备。
//
// 先在锁内取地址快照、再在锁外发送：持锁做网络写入会把整张设备表
// （含注册/下线/心跳）一起堵住，广播本身又不紧急，不值得冒这个险。
func (s *Server) flood(conn *net.UDPConn, pkt []byte, exceptVIP uint32) {
	s.mu.Lock()
	addrs := make([]*net.UDPAddr, 0, len(s.devices))
	for vip, d := range s.devices {
		if vip == exceptVIP || d.UDPAddr == nil {
			continue
		}
		addrs = append(addrs, d.UDPAddr)
	}
	s.mu.Unlock()

	for _, a := range addrs {
		if _, err := conn.WriteToUDP(pkt, a); err != nil {
			log.Printf("[server] 广播转发失败: %v", err)
		}
	}
}

var errNameTaken = &nameTakenError{}

type nameTakenError struct{}

func (*nameTakenError) Error() string { return protocol.ErrNameTakenMsg }

// ParseVIP 将点分十进制虚拟 IP 字符串解析为 uint32。
func ParseVIP(s string) (uint32, error) {
	return protocol.IP4(s)
}

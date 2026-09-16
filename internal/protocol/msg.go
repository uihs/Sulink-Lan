// Package protocol 定义客户端与服务端之间的信令消息格式。
// 信令通道使用 TCP + 长度前缀 + JSON：4 字节大端长度 + JSON 载荷。
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
)

// MsgType 信令消息类型。
type MsgType uint8

const (
	MsgChallenge   MsgType = 0  // 服务端 -> 客户端：认证挑战（随机 nonce）
	MsgHello       MsgType = 1  // 客户端 -> 服务端：注册（携带设备名 + 认证标签）
	MsgWelcome     MsgType = 2  // 服务端 -> 客户端：分配虚拟 IP、下发服务器信息
	MsgPeerList    MsgType = 3  // 服务端 -> 客户端：在线设备列表
	MsgHoleRequest MsgType = 4  // 客户端 -> 服务端：请求对端打洞信息
	MsgHoleNotify  MsgType = 5  // 服务端 -> 客户端：对端打洞信息（双方同时收到）
	MsgPeerOnline  MsgType = 6  // 服务端 -> 客户端：某设备上线
	MsgPeerOffline MsgType = 7  // 服务端 -> 客户端：某设备下线
	MsgHeartbeat   MsgType = 8  // 客户端 -> 服务端：心跳保活
	MsgError       MsgType = 9  // 服务端 -> 客户端：错误通知
	MsgConfigPush  MsgType = 10 // 服务端 -> 客户端：下发全局配置（公告 / 禁止打洞，管理页触发）
	// MsgForwardGet / MsgForwardPush 是**设备级**穿透规则的通道。
	//
	// 为什么不复用 MsgConfigPush 的 Config map：两者作用域根本不同。
	// 公告、禁止打洞是「对所有人一视同仁」的全局策略，走广播；
	// 穿透规则是「这台设备该暴露哪个内网服务」，按设备标识逐台下发。
	// 混在同一个 map 里，服务端就得回答「这台设备的 forward 和全局的 forward 谁优先」——
	// 一个本不该存在的问题，而且迟早会有人配错。
	MsgForwardGet  MsgType = 11 // 客户端 -> 服务端：查询本设备的穿透规则
	MsgForwardPush MsgType = 12 // 服务端 -> 客户端：本设备的穿透规则（连接时与变更时各发一次）
	// MsgProxyOpen/Close/Abort/Ready 是**已废弃**的公网端口映射信令，编号保留、
	// 两侧实现均已删除（客户端见 a8d3bfd，服务端见 4ea53c7）。
	//
	// 为什么不复用 ForwardPush 曾有过一套理由（公网映射是「外网 -> 服务端 ->
	// 客户端 -> 内网目标」，内网穿透是「虚拟网络内设备 -> 客户端 -> 内网目标」，
	// 流量来源与生命周期不同）——但最终结论是这套东西整体不做了：公网访问改由
	// NPS / npc 承担（管理页「公网访问（npc）」卡片，端点 /api/nps/*），
	// 自己实现既要维护动态端口监听，又要跟 NPS 抢同一件事，得不偿失。
	//
	// 编号留空而不再分配给别的用途：这些值已出现在历史版本客户端与服务端的
	// 线路上，回收复用会让旧版本把新信令误读成代理信令，造成难以定位的串扰。
	MsgProxyOpen  MsgType = 13 // 已废弃：服务端 -> 客户端：新的公网连接已建立
	MsgProxyClose MsgType = 14 // 已废弃：服务端 -> 客户端：公网连接已断开
	MsgProxyAbort MsgType = 15 // 已废弃：客户端 -> 服务端：公网会话建立失败
	MsgProxyReady MsgType = 16 // 已废弃：客户端 -> 服务端：代理会话已就绪
	// MsgRegister / MsgRegisterOK 是「自动注册」的通道。
	//
	// 为什么需要注册这一步：设备要有自己的长期凭证（设备 ID + 密钥），
	// 且认证身份要与硬件绑定。客户端打开软件时凭本机设备标识（HWID）
	// 向服务端申请：首次签发新凭证，再次连接复用原凭证；响应用
	// HWID 派生的密钥加密——HWID 是本地已知量，凭证在握手内安全到达，
	// 无需任何手工分发（无预共享密钥、无注册码）。
	MsgRegister   MsgType = 17 // 客户端 -> 服务端：携带 HWID，申请/复用设备凭证
	MsgRegisterOK MsgType = 18 // 服务端 -> 客户端：加密的设备凭证包（Blob）
)

// 下发配置的约定键名。
//
// 为什么用「字符串键的映射」而不是给每个配置项加一个结构体字段：
// 管理页要下发的东西会随版本演进不断增加，若每加一项都要改协议结构、
// 同时保证新旧两端都能解析，升级会很痛苦。用 map 后，老客户端遇到
// 不认识的键只需忽略——协议天然向前兼容，新键可以随时加。
//
// 代价是键名没有编译期检查，因此集中在此处定义常量，
// 服务端、客户端、管理页三处引用同一组常量，避免拼写漂移。
const (
	CfgNotice  = "notice"   // 公告文本：客户端以横幅展示，空串表示清除
	CfgNoPunch = "no_punch" // "1"/"true"：禁止 P2P 打洞，强制走服务器中转
)

// ParseBool 解析下发配置里的布尔值，容忍 "1"/"true"/"on"/"yes" 等写法。
//
// 管理页是手输表单，用户不会严格按 "true" 填写，这里统一宽松处理。
func ParseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes", "y", "是", "开":
		return true
	}
	return false
}

// ErrNameTakenMsg 设备名冲突错误文案（客户端据此识别致命错误，不无限重试）。
const ErrNameTakenMsg = "device name already online"

// ErrAuthFailedMsg 认证失败错误文案。
// 客户端据此判定为致命错误：密钥不对时重试永远不可能成功，
// 与其每 2 秒重连一次刷屏，不如直接停下并告诉用户改密钥。
const ErrAuthFailedMsg = "authentication failed"

func (t MsgType) String() string {
	switch t {
	case MsgChallenge:
		return "Challenge"
	case MsgHello:
		return "Hello"
	case MsgWelcome:
		return "Welcome"
	case MsgPeerList:
		return "PeerList"
	case MsgHoleRequest:
		return "HoleRequest"
	case MsgHoleNotify:
		return "HoleNotify"
	case MsgPeerOnline:
		return "PeerOnline"
	case MsgPeerOffline:
		return "PeerOffline"
	case MsgHeartbeat:
		return "Heartbeat"
	case MsgError:
		return "Error"
	case MsgConfigPush:
		return "ConfigPush"
	case MsgForwardGet:
		return "ForwardGet"
	case MsgForwardPush:
		return "ForwardPush"
	case MsgProxyOpen:
		return "ProxyOpen"
	case MsgProxyClose:
		return "ProxyClose"
	case MsgProxyAbort:
		return "ProxyAbort"
	case MsgProxyReady:
		return "ProxyReady"
	case MsgRegister:
		return "Register"
	case MsgRegisterOK:
		return "RegisterOK"
	default:
		return fmt.Sprintf("Msg(%d)", uint8(t))
	}
}

// Message 是所有信令消息的统一信封。
type Message struct {
	Type MsgType `json:"t"`
	// 以下字段按消息类型取用：
	DeviceName string `json:"name,omitempty"` // Hello
	// HWID 设备稳定标识（Hello/Register）：服务端据此发放 IP 租约与设备凭证，
	// 让同一台设备每次上线都拿回同一个虚拟 IP、同一份凭证。
	// 客户端必须携带它才能完成自动注册；空串会被服务端拒绝注册。
	HWID  string `json:"hwid,omitempty"` // Hello/Register：设备稳定标识
	Nonce []byte `json:"nonce,omitempty"` // Challenge：服务器下发的随机挑战值
	Auth  []byte `json:"auth,omitempty"`  // Hello/Register：认证标签 HMAC-SHA256(authKey, nonce)
	// DeviceID 设备凭证标识（Hello）：认证时携带，服务端据此查表找到
	// 该设备的密钥验证 Auth。自动注册后客户端必定持有凭证，必带此字段。
	DeviceID string `json:"deviceId,omitempty"`
	// Blob 加密的设备凭证包（RegisterOK）：AES-GCM，密钥由设备标识派生，
	// 载荷为 JSON 序列化的 Credential（设备 ID + 密钥 + 网络密钥）。
	// 见 EncryptCredential / DecryptCredential。
	Blob []byte `json:"blob,omitempty"`
	// NetworkKey 数据面网络密钥（Welcome，旧版下发用）。凭证设备在注册
	// 响应里已经拿到网络密钥，不再需要 Welcome 重复下发；保留字段仅用于
	// 兼容旧版客户端的消息解析。
	NetworkKey []byte `json:"networkKey,omitempty"`
	VIP        uint32 `json:"vip,omitempty"` // 虚拟 IP（网络字节序存储，见 IP4 helper）
	// LeaseUntil 本机虚拟 IP 的租约到期时刻（Unix 秒，Welcome）。
	// 客户端展示它，让用户知道「这个地址会保留到什么时候」——
	// 否则地址突然变化时用户没有任何线索可循。
	LeaseUntil int64  `json:"leaseUntil,omitempty"`
	PeerVIP    uint32 `json:"peer,omitempty"`  // HoleRequest：目标设备虚拟 IP
	Addrs      []Addr `json:"addrs,omitempty"` // HoleNotify：对端的候选公网地址
	Error      string `json:"err,omitempty"`   // Error
	Peers      []Peer `json:"peers,omitempty"` // PeerList / PeerOnline
	// Config 下发配置项（ConfigPush）。键名见 CfgNotice / CfgNoPunch。
	Config map[string]string `json:"cfg,omitempty"`
	// Rules 本设备的穿透规则（ForwardGet / ForwardPush），形如 "8080=192.168.1.5:80"。
	//
	// 用切片而不是多行文本：规则天生是一组，切片让「没有规则」与
	// 「一条空规则」不可能混淆，也省掉两端各自实现一遍分隔符解析。
	Rules []string `json:"rules,omitempty"`
	// ProxySession 公网端口映射的会话标识（ProxyOpen / ProxyClose）。
	// SessionID 由服务端生成，同一连接生命周期内保持不变。
	ProxySession uint32 `json:"proxySession,omitempty"`
	// ProxyProto 内网目标的传输层协议（ProxyOpen）："tcp" / "udp"。
	// 客户端据此决定用哪种协议拨号内网目标；缺省按 tcp 处理（老服务端不带此字段）。
	ProxyProto string `json:"proxyProto,omitempty"`
	// ProxyVPort 公网端口映射对应的虚拟端口（ProxyOpen）。
	// 客户端据此知道该把流量转发到哪个内网目标。
	ProxyVPort uint16 `json:"proxyVPort,omitempty"`
}

// VNetCIDR 虚拟局域网的网段，固定为 10.0.0.0/8。
//
// 为什么写死而不是可配置：网段可配置会带来两类难以排查的故障——
// 两端配置不一致时，服务端按自己的地址池分配 VIP、客户端却按另一个网段建路由，
// 表现为「信令已上线但 ping 不通」；网段与本机物理网络重叠时，穿透又会静默失效。
// 与其让用户在两处配置里自行保证一致，不如由代码统一约定——
// 统一网段反而消除了整整一类故障。
//
// 选用 10.0.0.0/8（RFC 1918 私有段）：容量约 1600 万，
// 不会像 /24 那样在设备多时耗尽。
//
// 注意：若本机所在局域网也用 10.x（部分企业网、校园网如此），
// 该网段会与之重叠导致穿透失效，此时需更换物理网络环境。
const VNetCIDR = "10.0.0.0/8"

// VNetBroadcast 虚拟网段的定向广播地址（由 VNetCIDR 推导，当前为 10.255.255.255）。
//
// 它在协议里有一个专门用途：作为「泛洪」的哨兵目标。
// 三层隧道只转发单播——客户端把包发往广播地址后，服务端按目标 VIP 查表
// 必然查不到（广播地址从不分配给设备），包会被静默丢弃，表现为
// 「虚拟局域网内互相发现不了」。约定这个地址后，服务端就能识别出
// 「这是广播，应转发给所有在线设备」而不是丢弃（见 server.relayLoop）。
//
// 用变量而非常量：值要从 VNetCIDR 推导，无法写成编译期常量。
// 解析失败属于编码错误（内置常量写错），直接 panic 比带着坏地址继续跑更安全，
// 而且测试会第一时间拦住。
var VNetBroadcast = func() uint32 {
	_, ipnet, err := net.ParseCIDR(VNetCIDR)
	if err != nil {
		panic("内置网段 " + VNetCIDR + " 无法解析: " + err.Error())
	}
	// 广播地址 = 网络地址 | ~掩码
	return binary.BigEndian.Uint32(ipnet.IP.To4()) | ^binary.BigEndian.Uint32(ipnet.Mask)
}()

// Addr 一个 UDP 候选地址（打洞用）。
type Addr struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Peer 设备信息（列表项）。
type Peer struct {
	Name string `json:"name"`
	VIP  uint32 `json:"vip"`
}

// IP4 将点分十进制字符串转成 uint32（网络字节序，便于直接写入 IP 头）。
func IP4(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("bad ipv4: %s", s)
	}
	return binary.BigEndian.Uint32(ip), nil
}

// IP4String 将 uint32（网络字节序）转回点分十进制。
func IP4String(v uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip.String()
}

// WriteMsg 写一条消息：4 字节大端长度 + JSON 载荷。
func WriteMsg(w io.Writer, m *Message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ReadMsg 读一条消息。
func ReadMsg(r io.Reader) (*Message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 1<<20 { // 最大 1MB，防异常
		return nil, fmt.Errorf("msg too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var m Message
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

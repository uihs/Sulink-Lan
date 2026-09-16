package server

import (
	"fmt"
	"log"
	"strings"
	"time"

	"sulink-lan/internal/protocol"
)

// 本文件是服务端的管理接口，供 Web 管理页（internal/admin）调用。
//
// 为什么放在 server 包内而不是让 admin 包直接操作 Server：
// 这些操作都要读写设备表、下发配置、统计计数——全是 Server 的内部状态。
// 若跨包访问，就得把 mu / devices / pushed 这些字段导出，
// 等于把内部并发约束（谁能持锁、锁序如何）暴露给调用方，
// 日后任何一处忘记加锁都会变成难以复现的数据竞争。
// 因此这里只暴露「语义化动作」，锁的边界留在 server 包内部。

// DeviceInfo 一台在线设备的对外快照（管理页展示用）。
//
// 注意不含任何密钥材料；UDP 地址是客户端 NAT 后的公网映射，
// 属于运维需要看到的信息（排查打洞失败时第一眼就看它）。
type DeviceInfo struct {
	Name       string `json:"name"`
	HWID       string `json:"hwid"`
	VIP        string `json:"vip"`
	UDPAddr    string `json:"udpAddr"`
	OnlineSecs int64  `json:"onlineSecs"`
}

// LeaseInfo 一台设备的服务端记录（IP 租约 + 穿透规则）的对外快照。
//
// 与 DeviceInfo 的区别：DeviceInfo 是「此刻在线的是谁」（含 NAT 地址、在线时长），
// LeaseInfo 是「服务端替哪些设备记住了什么」（含离线设备）。
// 管理页两张表各回答一个问题，因此不合并。
type LeaseInfo struct {
	HWID       string   `json:"hwid"`
	Name       string   `json:"name"`
	VIP        string   `json:"vip"` // 空串表示尚未分配地址（设备还没上线过）
	Online     bool     `json:"online"`
	ExpireAt   int64    `json:"expireAt"`   // Unix 秒；0 表示无租约
	RemainSecs int64    `json:"remainSecs"` // 距到期剩余秒数
	Forward    []string `json:"forward"`    // 该设备的穿透规则
	// Registered 是否已登记设备凭证（自动注册后必有）。管理页据此显示
	// 「已注册 / 未注册」并提供清除凭证入口。
	Registered bool `json:"registered"`
	// Blocked 是否被管理员封禁（清凭证/踢下线后置位，解除封禁后清除）。
	Blocked bool `json:"blocked"`
}

// Stats 服务端运行统计。
type Stats struct {
	PktsRelayed  uint64 `json:"pktsRelayed"`  // 中继转发的数据包
	BytesRelayed uint64 `json:"bytesRelayed"` // 中继转发的字节
	PktsFlooded  uint64 `json:"pktsFlooded"`  // 广播泛洪次数
	ICMPReplies  uint64 `json:"icmpReplies"`  // 合成的 ICMP 应答
	PktsRejected uint64 `json:"pktsRejected"` // 认证失败被丢弃的包
}

// Snapshot 服务端整体状态（管理页一次拉全，避免前端多次往返）。
type Snapshot struct {
	ServerVIP string            `json:"serverVip"`
	VNet      string            `json:"vnet"`
	TCPAddr   string            `json:"tcpAddr"`
	UDPAddr   string            `json:"udpAddr"`
	Uptime    int64             `json:"uptimeSecs"`
	Devices   []DeviceInfo      `json:"devices"`
	Leases    []LeaseInfo       `json:"leases"`
	LeaseDays int               `json:"leaseDays"` // 租约时长（天），管理页展示用
	Pushed    map[string]string `json:"pushed"`
	Stats     Stats             `json:"stats"`
}

// Snapshot 返回当前服务端状态。
func (s *Server) Snapshot() Snapshot {
	now := time.Now()
	s.mu.Lock()
	devices := make([]DeviceInfo, 0, len(s.devices))
	// 顺手记下此刻在线的地址，供设备表标记在线状态。
	// 不在持有设备表锁时回头去查 s.mu——两把锁的获取顺序必须始终如一，
	// 否则某个并发路径一反向就是死锁。
	onlineVIP := make(map[uint32]bool, len(s.devices))
	for _, d := range s.devices {
		onlineVIP[d.VIP] = true
		udp := ""
		if d.UDPAddr != nil {
			udp = d.UDPAddr.String()
		}
		devices = append(devices, DeviceInfo{
			Name:       d.Name,
			HWID:       d.HWID,
			VIP:        protocol.IP4String(d.VIP),
			UDPAddr:    udp,
			OnlineSecs: int64(now.Sub(d.OnlineAt).Seconds()),
		})
	}
	s.mu.Unlock()

	s.addrMu.Lock()
	tcpAddr, udpAddr := s.tcpAddr, s.udpAddr
	s.addrMu.Unlock()

	leases := s.deviceTable.Snapshot(now, func(vip uint32) bool { return onlineVIP[vip] })

	return Snapshot{
		ServerVIP: protocol.IP4String(s.ipPool.ServerVIP()),
		VNet:      protocol.VNetCIDR,
		TCPAddr:   tcpAddr,
		UDPAddr:   udpAddr,
		Uptime:    int64(now.Sub(s.started).Seconds()),
		Devices:   devices,
		Leases:    leases,
		LeaseDays: int(LeaseDuration.Hours() / 24),
		Pushed:    s.PushedConfig(),
		Stats: Stats{
			PktsRelayed:  s.statPkts.Load(),
			BytesRelayed: s.statBytes.Load(),
			PktsFlooded:  s.statFlooded.Load(),
			ICMPReplies:  s.statICMP.Load(),
			PktsRejected: s.statRejected.Load(),
		},
	}
}

// PushedConfig 返回当前生效的下发配置副本。
func (s *Server) PushedConfig() map[string]string {
	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	return copyMap(s.pushed)
}

// Push 合并并下发全局配置（公告 / 禁止打洞），返回实际收到下发的在线设备数。
//
// 合并语义（而不是整体替换）：管理页是「按项修改」的界面，
// 管理员改公告时不应该把之前下发的 no_punch 一起抹掉。
// 值留空表示清除该项——这正是管理页「删除公告」按钮的实现方式，
// 不需要额外做一个删除接口。
//
// 改动会立刻落盘：公告发出去之后，哪怕服务端重启，新上线的设备
// 也必须还能看到它。落盘失败只记日志、不阻断下发——磁盘只读时
// 「管理页点了没反应」比「重启后丢失」更难排查，
// 所以先把配置发下去，同时把失败明确写进日志。
func (s *Server) Push(cfg map[string]string) int {
	s.pushMu.Lock()
	for k, v := range cfg {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.TrimSpace(v) == "" {
			delete(s.pushed, k)
			continue
		}
		s.pushed[k] = v
	}
	merged := copyMap(s.pushed)
	path := s.settingsPath
	s.pushMu.Unlock()

	if err := saveSettings(path, merged); err != nil {
		log.Printf("[server] 全局配置写入失败（%s），本次改动在服务端重启后会丢失: %v", path, err)
	}

	return s.broadcast(&protocol.Message{Type: protocol.MsgConfigPush, Config: merged})
}

// SetDeviceForward 设置某设备的穿透规则（管理页调用），返回是否已推送给在线设备。
//
// 客户端没有本地规则配置入口，这里是规则的唯一来源：
// 「哪台机器该暴露哪个内网服务」因此只在一处维护，管理员能一眼看到全貌。
//
// 注意推送给在线设备的是**落盘后读回来的那份规则**，而不是传进来的参数。
// 二者在今天是等价的（SetForward 只做校验、不改内容），但一旦将来加了
// 规范化、去重或截断，推送值就会和「设备下次上线时拿到的值」分叉——
// 那意味着在线设备与离线设备最终生效的规则不一样，且没有任何地方看得出来。
func (s *Server) SetDeviceForward(hwid string, rules []string) (bool, error) {
	if err := s.deviceTable.SetForward(hwid, rules); err != nil {
		return false, err
	}
	target := s.findByHWID(hwid)
	if target == nil {
		// 设备离线：规则已存下，等它下次上线时主动查询即可。
		return false, nil
	}
	s.sendMsg(target, &protocol.Message{
		Type:  protocol.MsgForwardPush,
		Rules: s.deviceTable.Forward(hwid),
	})
	return true, nil
}

// SetDeviceIP 手工指定某设备的虚拟 IP（管理页「改地址」），返回是否触发了重连。
//
// 关于在线设备如何生效：虚拟网卡的地址是连接时配置的，运行中改不了
// （TUN 层不支持热改地址，各平台都要重建网卡）。因此这里改完租约后
// **主动断开该设备**，客户端会在 2 秒内自动重连并拿到新地址。
//
// 为什么不「只改记录、等它下次自然重连」：那样管理页显示已改成新地址、
// 设备实际却还在用旧地址，而且没有任何地方能看出这个差异——
// 属于典型的「点了没反应」。断开重连虽然粗暴，但结果与显示一致。
func (s *Server) SetDeviceIP(hwid, vipStr string) (bool, error) {
	vip, err := protocol.IP4(vipStr)
	if err != nil {
		return false, fmt.Errorf("虚拟地址格式不正确: %s", vipStr)
	}
	if err := s.deviceTable.SetIP(hwid, vip, s.ipPool); err != nil {
		return false, err
	}
	dev := s.findByHWID(hwid)
	if dev == nil || dev.Conn == nil {
		return false, nil // 设备离线：改租约即可，下次上线即用新地址
	}
	dev.Conn.Close()
	return true, nil
}

// findByHWID 按设备标识查找在线设备；找不到返回 nil。
//
// 设备表很小（一台服务器上通常几十台），线性扫描足够；
// 为此再维护一张 HWID -> Device 的索引，只会多一份需要保持同步的状态。
func (s *Server) findByHWID(hwid string) *Device {
	if hwid == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.HWID == hwid {
			return d
		}
	}
	return nil
}

// broadcast 向所有在线设备投递一条信令消息，返回投递数量。
//
// 先在锁内取设备快照、再在锁外投递：sendMsg 内部要拿每台设备自己的 mu，
// 若在持 s.mu 期间调用，就把「设备表锁」和「设备写队列锁」串成了一条锁链，
// 任何一处阻塞都会连带卡住注册与下线。
func (s *Server) broadcast(m *protocol.Message) int {
	s.mu.Lock()
	devices := make([]*Device, 0, len(s.devices))
	for _, d := range s.devices {
		devices = append(devices, d)
	}
	s.mu.Unlock()

	for _, d := range devices {
		s.sendMsg(d, m)
	}
	return len(devices)
}

// RevokeDeviceCredential 清除设备的注册凭证并封禁它（管理页「清除凭证」）。
//
// 为什么顺带封禁：原本只清凭证时，设备凭 HWID 走自动注册立刻拿回新凭证，
// 等于没清。封禁后 handleRegister 直接拒绝该 HWID，设备才真的进不来。
// 管理员在管理页「解除封禁」（UnblockDevice）后恢复。
func (s *Server) RevokeDeviceCredential(hwid string) bool {
	if s.deviceTable.Block(hwid) {
		if dev := s.findByHWID(hwid); dev != nil && dev.Conn != nil {
			dev.Conn.Close() // 在线设备立刻断开
		}
		log.Printf("[server] 设备 %s 已被清除凭证并封禁", shortHWID(hwid))
		return true
	}
	return false
}

// UnblockDevice 解除设备封禁（管理页「解除封禁」）。
func (s *Server) UnblockDevice(hwid string) bool {
	if s.deviceTable.Unblock(hwid) {
		log.Printf("[server] 设备 %s 已解除封禁", shortHWID(hwid))
		return true
	}
	return false
}

// copyMap 复制一份 map，避免把内部状态直接交给调用方（尤其是并发读的场景）。
func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

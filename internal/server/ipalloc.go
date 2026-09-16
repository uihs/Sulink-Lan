package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"sulink-lan/internal/protocol"
)

// IPPool 虚拟 IP 分配器。
// 从固定的虚拟网段内分配，保留网络地址、广播地址和 0.1（服务器自身）。
type IPPool struct {
	mu      sync.Mutex
	netAddr uint32 // 网段网络地址（网络字节序）
	start   uint32 // 第一个可分配 IP
	end     uint32 // 最后一个可分配 IP
	used    map[uint32]bool
}

// NewIPPool 按固定的虚拟网段初始化分配器。
//
// 网段不再作为参数传入：它由 protocol.VNetCIDR 统一约定，
// 服务端与客户端在地址空间上天然一致，不存在「两端网段配得不一样」这类故障。
func NewIPPool() (*IPPool, error) {
	_, ipnet, err := net.ParseCIDR(protocol.VNetCIDR)
	if err != nil {
		// 内置常量写错属于编码错误（测试会拦住），但这里仍显式报错，
		// 避免带着一个损坏的地址池继续运行——那会让故障延后到分配地址时才暴露。
		return nil, fmt.Errorf("内置网段 %s 无法解析: %w", protocol.VNetCIDR, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("内置网段 %s 不是 IPv4", protocol.VNetCIDR)
	}
	netAddr := binary.BigEndian.Uint32(ipnet.IP.To4())
	hostBits := uint32(1) << uint(32-ones)
	broadcast := netAddr | (hostBits - 1)

	// 保留网段首地址（网络地址）、服务器自身 .1、广播地址。
	start := netAddr + 2
	end := broadcast - 1
	if end < start {
		return nil, fmt.Errorf("内置网段 %s 无可用地址", protocol.VNetCIDR)
	}
	return &IPPool{
		netAddr: netAddr,
		start:   start,
		end:     end,
		used:    make(map[uint32]bool),
	}, nil
}

// ServerVIP 返回服务器自身在虚拟网络中的 IP（网段 .1）。
func (p *IPPool) ServerVIP() uint32 {
	return p.netAddr + 1
}

// Alloc 分配一个空闲虚拟 IP；网段满时返回错误。
func (p *IPPool) Alloc() (uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ip := p.start; ip <= p.end; ip++ {
		if !p.used[ip] {
			p.used[ip] = true
			return ip, nil
		}
	}
	return 0, errors.New("virtual ip pool exhausted")
}

// AllocAt 占用指定的虚拟 IP（IP 租约「把地址还给同一台设备」时用）。
// 地址越界或已被占用时返回错误。
func (p *IPPool) AllocAt(ip uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.inRangeLocked(ip) {
		return fmt.Errorf("地址 %s 不在可分配范围内", protocol.IP4String(ip))
	}
	if p.used[ip] {
		return fmt.Errorf("地址 %s 已被占用", protocol.IP4String(ip))
	}
	p.used[ip] = true
	return nil
}

// Held 报告地址当前是否已被占用（在可分配范围内且已分配出去）。
func (p *IPPool) Held(ip uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.used[ip]
}

// InRange 报告地址是否落在可分配范围内。
//
// 注意它排除三类地址：网络地址、服务器自身的 .1、广播地址。
// 管理页允许手工指定 IP，必须用这里拦住「把 10.0.0.1 分给客户端」
// 或「把 10.255.255.255 分出去」——后者会让泛洪哨兵语义彻底错乱。
func (p *IPPool) InRange(ip uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inRangeLocked(ip)
}

// inRangeLocked 是 InRange 的无锁版本，调用方必须已持有 p.mu。
func (p *IPPool) inRangeLocked(ip uint32) bool {
	return ip >= p.start && ip <= p.end
}

// Release 释放虚拟 IP。
func (p *IPPool) Release(ip uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, ip)
}

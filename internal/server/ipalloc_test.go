package server

import (
	"encoding/binary"
	"net"
	"testing"
)

// u32ip 便于把分配结果转成点分字符串做断言。
func u32ip(v uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b).String()
}

// TestNewIPPoolDefaultCIDR 内置网段 10.0.0.0/8 必须可用且边界正确。
//
// /8 是最大的一类 RFC1918 网段（约 1600 万地址），
// 一旦边界算错，最先分配给用户的就是网络地址或广播地址，直接不可用。
func TestNewIPPoolDefaultCIDR(t *testing.T) {
	p, err := NewIPPool()
	if err != nil {
		t.Fatalf("内置网段应可用: %v", err)
	}

	// 服务器自身固定占用网段 .1
	if got := u32ip(p.ServerVIP()); got != "10.0.0.1" {
		t.Fatalf("服务器 VIP 应为 10.0.0.1，实际 %s", got)
	}

	// 首个可分配地址必须跳过网络地址（10.0.0.0）与服务器地址（10.0.0.1）
	first, err := p.Alloc()
	if err != nil {
		t.Fatalf("分配失败: %v", err)
	}
	if got := u32ip(first); got != "10.0.0.2" {
		t.Fatalf("首个可用地址应为 10.0.0.2，实际 %s", got)
	}

	// 网段末尾应是 10.255.255.254（广播地址 10.255.255.255 必须排除）
	if got := u32ip(p.end); got != "10.255.255.254" {
		t.Fatalf("末个可用地址应为 10.255.255.254，实际 %s", got)
	}
	// 广播地址不得落入可分配区间
	if p.end >= p.netAddr|0x00FFFFFF {
		t.Fatal("广播地址不应被纳入可分配范围")
	}
}

// TestIPPoolAllocUniqueAndRelease 分配必须唯一，释放后可重新分配。
func TestIPPoolAllocUniqueAndRelease(t *testing.T) {
	p, err := NewIPPool()
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[uint32]bool)
	var first uint32
	for i := 0; i < 10; i++ {
		ip, err := p.Alloc()
		if err != nil {
			t.Fatalf("第 %d 次分配失败: %v", i+1, err)
		}
		if seen[ip] {
			t.Fatalf("地址 %s 被重复分配", u32ip(ip))
		}
		seen[ip] = true
		if i == 0 {
			first = ip
		}
	}

	p.Release(first)
	ip, err := p.Alloc()
	if err != nil {
		t.Fatalf("释放后重新分配失败: %v", err)
	}
	if ip != first {
		t.Fatalf("释放的地址应被复用: 期望 %s，实际 %s", u32ip(first), u32ip(ip))
	}
}

// TestIPPoolExhausted 地址耗尽后必须返回错误，而不是死循环或返回 0。
//
// 网段写死后 NewIPPool 只能产出 /8（1600 万地址），无法遍历耗尽，
// 但「耗尽时报错」是一条真实的安全属性——若退化成死循环，
// 服务端会在一个已满的池上卡死。因此直接构造一个小池来守住它，
// 绕开构造函数是本测试刻意的选择。
func TestIPPoolExhausted(t *testing.T) {
	// 手工构造 3 个可用地址的小池（start=10, end=12）
	p := &IPPool{netAddr: 8, start: 10, end: 12, used: make(map[uint32]bool)}
	const capacity = 3

	for i := 0; i < capacity; i++ {
		if _, err := p.Alloc(); err != nil {
			t.Fatalf("第 %d 次分配意外失败: %v", i+1, err)
		}
	}
	if ip, err := p.Alloc(); err == nil {
		t.Fatalf("地址耗尽后应返回错误，实际返回 %s", u32ip(ip))
	}

	// 释放一个后应能再分配：确认耗尽判定不会把池永久锁死
	p.Release(10)
	ip, err := p.Alloc()
	if err != nil {
		t.Fatalf("释放后重新分配失败: %v", err)
	}
	if ip != 10 {
		t.Fatalf("应复用刚释放的地址 10，实际 %d", ip)
	}
}

// TestIPPoolCapacityIsConsistent 容量计算必须与 /8 网段边界一致。
//
// 写死网段后无法靠遍历验证边界，改为直接断言计算结果的数值，
// 守住「网络地址、服务器 .1、广播地址三者都被排除」这一性质。
func TestIPPoolCapacityIsConsistent(t *testing.T) {
	p, err := NewIPPool()
	if err != nil {
		t.Fatal(err)
	}
	// /8：2^24 = 16777216 个地址，扣除网络地址、服务器 .1、广播地址后剩 16777213
	const wantCapacity = 16777213
	got := uint64(p.end) - uint64(p.start) + 1
	if got != wantCapacity {
		t.Fatalf("/8 可用地址数应为 %d，实际 %d", wantCapacity, got)
	}
	// 首地址与末地址的具体取值（防止掩码算错导致范围整体偏移）
	if got := u32ip(p.start); got != "10.0.0.2" {
		t.Fatalf("首个可分配地址应为 10.0.0.2，实际 %s", got)
	}
	if got := u32ip(p.end); got != "10.255.255.254" {
		t.Fatalf("末个可分配地址应为 10.255.255.254，实际 %s", got)
	}
}

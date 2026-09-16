package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sulink-lan/internal/protocol"
)

// newTestTable 建一个只在内存里的设备表（path 为空即不落盘）。
func newTestTable(t *testing.T) (*DeviceTable, *IPPool) {
	t.Helper()
	pool, err := NewIPPool()
	if err != nil {
		t.Fatal(err)
	}
	return NewDeviceTable(""), pool
}

func mustIP(t *testing.T, s string) uint32 {
	t.Helper()
	ip, err := protocol.IP4(s)
	if err != nil {
		t.Fatalf("测试地址 %q 不合法: %v", s, err)
	}
	return ip
}

// TestAssignKeepsAddressAcrossReconnect 同一设备标识重复上线必须拿回同一个地址。
//
// 这是整个租约功能的核心承诺。若哪天有人把 Assign 改成「每次都新分配」，
// 用户看到的现象是「说好的固定地址，重启一次就变了」。
func TestAssignKeepsAddressAcrossReconnect(t *testing.T) {
	tbl, pool := newTestTable(t)
	now := time.Now()

	vip1, exp1, err := tbl.Assign("hwid-a", "pc-a", pool, now)
	if err != nil {
		t.Fatal(err)
	}
	// 断开（服务端不归还地址）后重新上线
	vip2, exp2, err := tbl.Assign("hwid-a", "pc-a", pool, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if vip1 != vip2 {
		t.Fatalf("同一设备标识应拿回同一地址，实际 %s -> %s",
			protocol.IP4String(vip1), protocol.IP4String(vip2))
	}
	if !exp2.After(exp1) {
		t.Fatalf("每次上线都应续租，到期时刻未推进: %s -> %s", exp1, exp2)
	}
	if got := exp2.Sub(now.Add(time.Hour)); got != LeaseDuration {
		t.Fatalf("租约时长应为 %s，实际 %s", LeaseDuration, got)
	}
	// 反向对照：换一个设备标识必须拿到不同的地址
	vip3, _, err := tbl.Assign("hwid-b", "pc-b", pool, now)
	if err != nil {
		t.Fatal(err)
	}
	if vip3 == vip1 {
		t.Fatal("不同设备标识不应拿到同一个地址")
	}
}

// TestAssignSurvivesRestart 设备表落盘后重载，地址归属不变。
//
// 租约只存在内存里的话，服务端一重启所有设备就换地址——
// 那和「固定地址」这个需求本身是矛盾的。
func TestAssignSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	pool, err := NewIPPool()
	if err != nil {
		t.Fatal(err)
	}
	tbl := NewDeviceTable(path)
	vip, _, err := tbl.Assign("hwid-a", "pc-a", pool, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := tbl.SetForward("hwid-a", []string{"8080=192.168.1.5:80"}); err != nil {
		t.Fatal(err)
	}

	// 模拟重启：新建一张表、新建一个池子，从同一个文件加载
	pool2, err := NewIPPool()
	if err != nil {
		t.Fatal(err)
	}
	tbl2 := NewDeviceTable(path)
	if n := tbl2.Len(); n != 1 {
		t.Fatalf("重载后应有 1 条记录，实际 %d", n)
	}
	vip2, _, err := tbl2.Assign("hwid-a", "pc-a", pool2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if vip != vip2 {
		t.Fatalf("重启后地址变了: %s -> %s", protocol.IP4String(vip), protocol.IP4String(vip2))
	}
	if got := tbl2.Forward("hwid-a"); len(got) != 1 || got[0] != "8080=192.168.1.5:80" {
		t.Fatalf("穿透规则未持久化: %v", got)
	}
}

// TestAssignReclaimsExpiredLease 过期租约在下次分配前被回收，地址可给别人。
func TestAssignReclaimsExpiredLease(t *testing.T) {
	tbl, pool := newTestTable(t)
	now := time.Now()

	vipA, _, err := tbl.Assign("hwid-a", "pc-a", pool, now)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.Held(vipA) {
		t.Fatal("分配后地址应被占用")
	}

	// 时间推进到租约到期之后：B 上线应能拿到 A 的地址（池子里只有它一个可用）
	later := now.Add(LeaseDuration + time.Minute)
	vipB, _, err := tbl.Assign("hwid-b", "pc-b", pool, later)
	if err != nil {
		t.Fatal(err)
	}
	if vipB != vipA {
		t.Fatalf("过期地址应被回收给新设备，实际 %s", protocol.IP4String(vipB))
	}

	// A 再上线时不能再拿回已属于 B 的地址，只能换一个
	vipA2, _, err := tbl.Assign("hwid-a", "pc-a", pool, later)
	if err != nil {
		t.Fatal(err)
	}
	if vipA2 == vipB {
		t.Fatalf("A 不应抢回已被 B 占用的地址 %s", protocol.IP4String(vipA2))
	}
}

// TestPruneKeepsForwardRules 回收地址时**保留**穿透规则。
//
// 规则是管理员手工配的，不该因为设备一个月没上线就被悄悄删掉。
func TestPruneKeepsForwardRules(t *testing.T) {
	tbl, pool := newTestTable(t)
	now := time.Now()
	vipA, _, err := tbl.Assign("hwid-a", "pc-a", pool, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tbl.SetForward("hwid-a", []string{"8080=192.168.1.5:80"}); err != nil {
		t.Fatal(err)
	}

	if n := tbl.Prune(now.Add(LeaseDuration+time.Hour), pool); n != 1 {
		t.Fatalf("应回收 1 条过期租约，实际 %d", n)
	}
	if tbl.Len() != 1 {
		t.Fatalf("回收地址不应删除记录，实际剩余 %d 条", tbl.Len())
	}
	if got := tbl.Forward("hwid-a"); len(got) != 1 {
		t.Fatalf("穿透规则被误删: %v", got)
	}
	// 反向对照：地址确实已归还池子，且反向索引也清干净了
	if pool.Held(vipA) {
		t.Fatalf("过期地址 %s 应已归还地址池", protocol.IP4String(vipA))
	}
	if _, exists := tbl.byVIP[vipA]; exists {
		t.Fatal("过期地址的 VIP->设备标识 索引未清理")
	}
}

// TestSetForwardValidatesBeforeWriting 非法规则必须整体拒绝，且不落盘。
//
// 服务端是规则的唯一入口：让一条坏规则写进去，客户端只会把它静默忽略，
// 管理员则以为「已经配好了」。
func TestSetForwardValidatesBeforeWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	tbl := NewDeviceTable(path)

	bad := []struct {
		name  string
		rules []string
	}{
		{"端口为 0", []string{"0=192.168.1.5:80"}},
		{"缺等号", []string{"8080"}},
		{"虚拟端口重复", []string{"8080=192.168.1.5:80", "8080=192.168.1.6:80"}},
		{"目标端口越界", []string{"8080=192.168.1.5:70000"}},
		{"目标 IP 非法", []string{"8080=not-an-ip:80"}},
	}
	for _, c := range bad {
		if err := tbl.SetForward("hwid-a", c.rules); err == nil {
			t.Fatalf("%s 应被拒绝: %v", c.name, c.rules)
		}
		if got := tbl.Forward("hwid-a"); len(got) != 0 {
			t.Fatalf("%s 被拒绝后不应留下任何规则，实际 %v", c.name, got)
		}
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("全部校验失败时不应写出文件")
	}

	// 合法规则可以写入，并且允许为「还没上线过的设备」预先配置
	if err := tbl.SetForward("hwid-future", []string{"19132=192.168.1.9:19132"}); err != nil {
		t.Fatalf("合法规则应被接受: %v", err)
	}
	if got := tbl.Forward("hwid-future"); len(got) != 1 {
		t.Fatalf("规则未写入: %v", got)
	}
	// 空规则表示取消穿透
	if err := tbl.SetForward("hwid-future", nil); err != nil {
		t.Fatal(err)
	}
	if got := tbl.Forward("hwid-future"); len(got) != 0 {
		t.Fatalf("清空后不应还有规则: %v", got)
	}
}

// TestSetIPValidates 手工改地址的三类拒绝：地址不可分配、已被占用、设备不存在。
func TestSetIPValidates(t *testing.T) {
	tbl, pool := newTestTable(t)
	now := time.Now()
	vipA, _, _ := tbl.Assign("hwid-a", "pc-a", pool, now)
	vipB, _, _ := tbl.Assign("hwid-b", "pc-b", pool, now)

	// 1) 设备不存在
	if err := tbl.SetIP("hwid-missing", mustIP(t, "10.0.0.9"), pool); err == nil {
		t.Fatal("对不存在的设备改地址应报错")
	}
	// 2) 越界地址：服务器自身地址、广播地址、网段外
	for _, bad := range []string{"10.0.0.1", "10.255.255.255", "192.168.1.1"} {
		if err := tbl.SetIP("hwid-a", mustIP(t, bad), pool); err == nil {
			t.Fatalf("地址 %s 不应可分配", bad)
		}
	}
	// 3) 已被别的设备占用
	if err := tbl.SetIP("hwid-a", vipB, pool); err == nil {
		t.Fatal("不应把已被占用的地址分配给另一台设备")
	}

	// 正向：改成池子里空闲的地址
	free := mustIP(t, "10.0.0.9")
	if err := tbl.SetIP("hwid-a", free, pool); err != nil {
		t.Fatalf("改成空闲地址应成功: %v", err)
	}
	if got := tbl.byHWID["hwid-a"].VIP; got != free {
		t.Fatalf("地址未更新: %s", protocol.IP4String(got))
	}
	// 旧地址已归还，新地址已占用
	if pool.Held(vipA) {
		t.Fatal("改地址后旧地址应被释放")
	}
	if !pool.Held(free) {
		t.Fatal("改地址后新地址应被占用")
	}
	// 幂等：改成当前地址不报错、不破坏状态
	if err := tbl.SetIP("hwid-a", free, pool); err != nil {
		t.Fatalf("改成同一地址应幂等成功: %v", err)
	}
	if !pool.Held(free) || tbl.byVIP[free] != "hwid-a" {
		t.Fatal("幂等调用破坏了地址归属")
	}
}

// TestSnapshotSortedAndMarksOnline 快照必须稳定排序，并正确标记在线状态。
//
// 不排序的话 map 遍历顺序随机，管理页每次刷新行序都在跳，
// 管理员想点某一行都得重新找。
func TestSnapshotSortedAndMarksOnline(t *testing.T) {
	tbl, pool := newTestTable(t)
	now := time.Now()
	// 按「不是分配顺序」的设备标识写入，确保排序不是巧合
	var assigned []uint32
	for _, h := range []string{"hwid-c", "hwid-a", "hwid-b"} {
		vip, _, err := tbl.Assign(h, h, pool, now)
		if err != nil {
			t.Fatal(err)
		}
		assigned = append(assigned, vip)
	}
	// 一条只有规则、没有地址的记录（设备还没上线过）
	if err := tbl.SetForward("hwid-z", []string{"8080=192.168.1.5:80"}); err != nil {
		t.Fatal(err)
	}

	// 只把第一台标记为在线，验证在线状态确实来自回调而不是「有地址就算在线」
	online := map[uint32]bool{assigned[0]: true}
	got := tbl.Snapshot(now, func(vip uint32) bool { return online[vip] })
	if len(got) != 4 {
		t.Fatalf("应有 4 条记录，实际 %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].VIP == "" && got[i].VIP != "" {
			t.Fatalf("无地址的记录应排在最后: %+v", got)
		}
		if got[i-1].VIP != "" && got[i].VIP != "" && got[i-1].VIP >= got[i].VIP {
			t.Fatalf("有地址的记录应按地址升序: %+v", got)
		}
	}
	if last := got[len(got)-1]; last.VIP != "" || len(last.Forward) != 1 {
		t.Fatalf("最后一条应是无地址但带规则的记录，实际 %+v", last)
	}

	onlineCount := 0
	for _, li := range got {
		if li.VIP == "" {
			continue
		}
		if li.RemainSecs <= 0 || li.ExpireAt == 0 {
			t.Fatalf("有地址的记录应带租约信息: %+v", li)
		}
		if li.Online {
			onlineCount++
		}
	}
	if onlineCount != 1 {
		t.Fatalf("在线标记应恰好命中 1 台，实际 %d", onlineCount)
	}
}

// TestDeviceFileShape 落盘结构是给人看的：地址存点分十进制、按设备标识排序。
//
// 这个文件在应急时是要手工改的，"10.0.0.2" 一眼能懂，167772162 得换算半天；
// 而顺序随机的文件每次 diff 都全变，版本管理就失去意义了。
func TestDeviceFileShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	pool, err := NewIPPool()
	if err != nil {
		t.Fatal(err)
	}
	tbl := NewDeviceTable(path)
	now := time.Now()
	// 故意乱序写入
	for _, h := range []string{"hwid-z", "hwid-a", "hwid-m"} {
		if _, _, err := tbl.Assign(h, h, pool, now); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f deviceFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 {
		t.Fatalf("版本号应为 1，实际 %d", f.Version)
	}
	if len(f.Devices) != 3 {
		t.Fatalf("应有 3 条记录，实际 %d", len(f.Devices))
	}
	for i := 1; i < len(f.Devices); i++ {
		if f.Devices[i-1].HWID >= f.Devices[i].HWID {
			t.Fatalf("记录应按设备标识排序: %v", f.Devices)
		}
	}
	for _, d := range f.Devices {
		if d.VIP == "" || d.VIP == "0.0.0.0" {
			t.Fatalf("地址应以点分十进制写出: %+v", d)
		}
		if d.ExpireAt.IsZero() {
			t.Fatalf("租约到期时刻应写出: %+v", d)
		}
	}
}

// TestCorruptDeviceFileQuarantined 损坏的设备表被隔离而不是覆盖，服务端照常启动。
//
// 最坏后果只是设备重新分配一次地址（可自愈），但那份坏文件必须留证，
// 否则「为什么我的地址全变了」永远查不出原因。
func TestCorruptDeviceFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	tbl := NewDeviceTable(path) // 不得 panic，也不得报错
	if tbl.Len() != 0 {
		t.Fatalf("损坏文件应退化为空表，实际 %d 条", tbl.Len())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	quarantined := 0
	for _, e := range entries {
		if e.Name() != "devices.json" {
			quarantined++
		}
	}
	if quarantined != 1 {
		t.Fatalf("损坏文件应被改名保留一份，目录内容: %v", entries)
	}
}

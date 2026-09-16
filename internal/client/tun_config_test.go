package client

import (
	"strings"
	"testing"

	"sulink-lan/internal/protocol"
)

// 本文件测试三个平台的网卡配置命令构造。
//
// 为什么这些测试很重要：命令构造是纯逻辑，但只有对应平台运行才能看到实际效果。
// 开发与 CI 都在 Linux 上，Windows/macOS 的分支无法真实执行，
// 一旦掩码、参数顺序写错，本地测试全绿、真机却 ping 不通——
// 本次「网卡掩码被配成 255.255.0.0」正是这类缺陷。
// 这些断言把「网卡必须 /32」这条约束固化下来，防止再次回归。

// 掩码相关：网卡地址必须配 /32，绝不能出现网段掩码。

// TestWindowsCommandsUseHostMask 守住 Windows 网卡必须配 /32。
func TestWindowsCommandsUseHostMask(t *testing.T) {
	cmds, err := windowsTunCommands("Sulink Lan", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var addrCmd *PlatformCommand
	for i := range cmds {
		if cmds[i].Name == "netsh" && containsSub(cmds[i].Args, "address") {
			addrCmd = &cmds[i]
		}
	}
	if addrCmd == nil {
		t.Fatal("未生成设置网卡地址的命令")
	}
	joined := strings.Join(addrCmd.Args, " ")
	if !strings.Contains(joined, hostMaskString) {
		t.Fatalf("网卡地址掩码必须为 %s（/32），实际命令: %s", hostMaskString, joined)
	}
	// 明确拒绝网段掩码：这类值一旦出现，跨主机流量会走 ARP 而不进 TUN
	for _, bad := range []string{"255.0.0.0", "255.255.0.0", "255.255.252.0"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("网卡地址不得使用网段掩码 %s（会导致 ARP 黑洞，ping 不通）: %s", bad, joined)
		}
	}
}

// TestDarwinCommandsUseHostMask 守住 macOS 网卡必须配 /32。
func TestDarwinCommandsUseHostMask(t *testing.T) {
	cmds, err := darwinTunCommands("utun4", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds[0].Args, " ")
	if !strings.Contains(joined, hostMaskString) {
		t.Fatalf("网卡掩码必须为 %s（/32），实际: %s", hostMaskString, joined)
	}
	for _, bad := range []string{"255.0.0.0", "255.255.0.0"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("网卡地址不得使用网段掩码 %s: %s", bad, joined)
		}
	}
}

// TestLinuxCommandsUseHostMask 守住 Linux 网卡必须配 /32。
func TestLinuxCommandsUseHostMask(t *testing.T) {
	cmds, err := linuxTunCommands("tun0", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var addrCmd *PlatformCommand
	for i := range cmds {
		if cmds[i].Name == "ip" && containsSub(cmds[i].Args, "addr") {
			addrCmd = &cmds[i]
		}
	}
	if addrCmd == nil {
		t.Fatal("未生成配置地址的命令")
	}
	joined := strings.Join(addrCmd.Args, " ")
	if !strings.Contains(joined, "10.0.0.2/32") {
		t.Fatalf("地址必须配成 ip/32，实际: %s", joined)
	}
	// 绝不能是 10.0.0.2/8 这类网段掩码
	if strings.Contains(joined, "10.0.0.2/8") || strings.Contains(joined, "/16") {
		t.Fatalf("地址不得使用网段掩码: %s", joined)
	}
}

// 参数构造：各平台的命令序列必须包含网段路由，否则流量出不去。

// TestCommandsIncludeCIDRRoute 三个平台都必须添加网段路由。
//
// 缺了这条路由的后果：/32 地址让接口不再「拥有」任何网段，
// 若没有网段路由，发往对端的包找不到出接口，直接被丢弃。
// 即「网卡配好了但完全不通」——比原来更难排查。
//
// 网段断言取自 protocol.VNetCIDR 而非本地字面量：
// 常量一旦被改动，这里的断言与实现保持同步失败，提醒改动者检查连带影响。
func TestCommandsIncludeCIDRRoute(t *testing.T) {
	cidr := protocol.VNetCIDR

	win, err := windowsTunCommands("Sulink Lan", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !hasCommandContaining(win, cidr) {
		t.Error("Windows 命令缺少网段路由")
	}

	lin, err := linuxTunCommands("tun0", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !hasCommandContaining(lin, cidr) {
		t.Error("Linux 命令缺少网段路由")
	}

	dar, err := darwinTunCommands("utun4", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !hasCommandContaining(dar, cidr) {
		t.Error("macOS 命令缺少网段路由")
	}
}

// TestWindowsRouteHasInterfaceAndNexthop 路由命令必须带接口与下一跳。
//
// /32 配置下接口没有可依附的 on-link 网段，netsh add route 若缺少
// nexthop 会报「参数错误」之类的失败，导致路由加不上。
// 这里断言两者都在，避免有人"简化"掉它们。
func TestWindowsRouteHasInterfaceAndNexthop(t *testing.T) {
	cmds, err := windowsTunCommands("Sulink Lan", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var routeCmd *PlatformCommand
	for i := range cmds {
		if containsSub(cmds[i].Args, "route") {
			routeCmd = &cmds[i]
		}
	}
	if routeCmd == nil {
		t.Fatal("未生成路由命令")
	}
	joined := strings.Join(routeCmd.Args, " ")
	if !strings.Contains(joined, "Sulink Lan") {
		t.Errorf("路由命令必须指定接口名，实际: %s", joined)
	}
	if !strings.Contains(joined, "10.0.0.2") {
		t.Errorf("路由命令必须指定下一跳（用自身地址即可），实际: %s", joined)
	}
}

// TestDarwinPointToPointForm utun 是点对点接口，ifconfig 必须给两个地址。
//
// ifconfig utunN inet <本端> <对端>：只给一个地址时系统会把它当作对端，
// 本端留空导致网卡不可用。这里断言地址出现了两次（本端=对端=自身）。
func TestDarwinPointToPointForm(t *testing.T) {
	cmds, err := darwinTunCommands("utun4", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds[0].Args, " ")
	if strings.Count(joined, "10.0.0.2") != 2 {
		t.Fatalf("点对点 ifconfig 需本端与对端各一个地址，实际: %s", joined)
	}
}

// TestDarwinRouteIsIdempotent macOS 的路由需先删后加。
//
// route add 对已存在路由会失败（File exists），重连时会中断本次连接。
// 先 delete 再 add 可保证「无论此前是否存在都成功」。
func TestDarwinRouteIsIdempotent(t *testing.T) {
	cmds, err := darwinTunCommands("utun4", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var hasDelete, hasAdd bool
	for _, c := range cmds {
		if c.Name == "route" && containsSub(c.Args, "delete") {
			hasDelete = true
		}
		if c.Name == "route" && containsSub(c.Args, "add") {
			hasAdd = true
		}
	}
	if !hasDelete || !hasAdd {
		t.Fatalf("macOS 路由需先 delete 再 add 以保证幂等，实际 hasDelete=%v hasAdd=%v", hasDelete, hasAdd)
	}
}

// TestLinuxUsesReplaceForIdempotency Linux 用 replace 保证重连幂等。
func TestLinuxUsesReplaceForIdempotency(t *testing.T) {
	cmds, err := linuxTunCommands("tun0", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var addrUsesReplace, routeUsesReplace bool
	for _, c := range cmds {
		if len(c.Args) >= 2 && c.Args[1] == "replace" {
			switch c.Args[0] {
			case "addr":
				addrUsesReplace = true
			case "route":
				routeUsesReplace = true
			}
		}
	}
	if !addrUsesReplace {
		t.Error("地址配置应使用 addr replace（add 在重连时会报 File exists）")
	}
	if !routeUsesReplace {
		t.Error("路由配置应使用 route replace")
	}
}

// TestWindowsAddressIsIdempotent Windows 网卡地址需先删后设。
//
// wintun 网卡断线时不会同步移除地址，快速重连时旧地址还挂在网卡上，
// netsh set address 对相同地址会报「对象已存在」并中断本次连接
// （本次线上故障即由此引发：踢下线后 2 秒重连，每次都卡在配地址上）。
// 先 delete 再 set 可保证「无论此前地址是否存在都成功」，
// 与 Linux 的 addr replace、macOS 的先删后加是同一语义。
func TestWindowsAddressIsIdempotent(t *testing.T) {
	cmds, err := windowsTunCommands("Sulink Lan", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var delIdx, setIdx = -1, -1
	for i, c := range cmds {
		if isDeleteAddressCommand(c) {
			delIdx = i
		}
		if c.Name == "netsh" && containsSub(c.Args, "set") && containsSub(c.Args, "address") {
			setIdx = i
		}
	}
	if delIdx == -1 {
		t.Fatal("地址配置缺少 delete address 步骤（先删后设才能保证重连幂等）")
	}
	if setIdx == -1 {
		t.Fatal("地址配置缺少 set address 步骤")
	}
	if delIdx >= setIdx {
		t.Fatalf("delete address 必须先于 set address 执行（实际 delete=%d set=%d）", delIdx, setIdx)
	}
	// 删除命令必须携带接口名与地址，否则删错对象或删不掉
	delCmd := cmds[delIdx]
	joined := strings.Join(delCmd.Args, " ")
	if !strings.Contains(joined, "Sulink Lan") || !strings.Contains(joined, "10.0.0.2") {
		t.Fatalf("delete address 必须指定接口名与地址，实际: %s", joined)
	}
}

// 入参校验：非法参数应尽早失败，避免生成会静默失效的命令。
//
// 网段不再是入参（固定为 protocol.VNetCIDR），故只校验网卡名与 IP。
// 若有人把网段重新做成入参，这里的测试表应同步补回网段用例。

func TestTunCommandsRejectInvalidInput(t *testing.T) {
	cases := []struct {
		name       string
		ifName, ip string
		wantErr    bool
	}{
		{"正常", "tun0", "10.0.0.2", false},
		{"网卡名为空", "", "10.0.0.2", true},
		{"IP 为空", "tun0", "", true},
		{"IP 非法", "tun0", "not-an-ip", true},
		{"IP 是网段", "tun0", "10.0.0.0/8", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := linuxTunCommands(c.ifName, c.ip)
			if (err != nil) != c.wantErr {
				t.Fatalf("linuxTunCommands(%q,%q) err=%v, wantErr=%v",
					c.ifName, c.ip, err, c.wantErr)
			}
			_, err = windowsTunCommands(c.ifName, c.ip)
			if (err != nil) != c.wantErr {
				t.Fatalf("windowsTunCommands err=%v, wantErr=%v", err, c.wantErr)
			}
			_, err = darwinTunCommands(c.ifName, c.ip)
			if (err != nil) != c.wantErr {
				t.Fatalf("darwinTunCommands err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

// 幂等错误识别：只应容忍「已存在」，其他错误必须上抛。

func TestIsBenignCommandError(t *testing.T) {
	routeAddWin := PlatformCommand{"netsh",
		[]string{"interface", "ip", "add", "route", "10.0.0.0/8", "tun", "10.0.0.2"}}
	addrSetWin := PlatformCommand{"netsh",
		[]string{"interface", "ip", "set", "address", "name=tun", "static", "10.0.0.2", "255.255.255.255"}}
	addrDelWin := PlatformCommand{"netsh",
		[]string{"interface", "ip", "delete", "address", "name=tun", "10.0.0.2"}}
	routeAddLin := PlatformCommand{"ip", []string{"route", "replace", "10.0.0.0/8", "dev", "tun0"}}
	routeAddDar := PlatformCommand{"route", []string{"-n", "add", "-net", "10.0.0.0/8", "10.0.0.2"}}

	cases := []struct {
		name string
		cmd  PlatformCommand
		out  string
		want bool
	}{
		{"Windows 路由已存在（英文）", routeAddWin, "The object already exists.", true},
		{"Windows 路由已存在（中文）", routeAddWin, "对象已存在。", true},
		{"Linux 路由已存在", routeAddLin, "RTNETLINK answers: File exists", true},
		{"macOS 路由已存在", routeAddDar, "route: writing to routing socket: File exists", true},
		{"Windows 设置地址失败不可忽略", addrSetWin, "The object already exists.", false},
		{"Windows 删除不存在地址（中文）", addrDelWin, "找不到元素。", true},
		{"Windows 删除不存在地址（英文）", addrDelWin, "The system cannot find the element specified.", true},
		{"权限不足必须上抛", routeAddWin, "请求的操作需要提升。", false},
		{"接口名错误必须上抛", routeAddDar, "route: bad address: nosuchif", false},
		{"空输出不可忽略", routeAddWin, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isBenignCommandError(c.cmd, c.out); got != c.want {
				t.Fatalf("isBenignCommandError(%v, %q) = %v, want %v",
					c.cmd.Args, c.out, got, c.want)
			}
		})
	}
}

// 辅助函数

func containsSub(args []string, sub string) bool {
	for _, a := range args {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}
func hasCommandContaining(cmds []PlatformCommand, sub string) bool {
	for _, c := range cmds {
		for _, a := range c.Args {
			if strings.Contains(a, sub) {
				return true
			}
		}
	}
	return false
}

package client

import (
	"fmt"
	"net"
	"strings"

	"sulink-lan/internal/protocol"
)

// 本文件集中放置三个平台共用的网卡配置逻辑与命令构造。
//
// 为什么不放在各自的 tun_<os>.go 里：这些函数是纯逻辑，不含任何系统调用，
// 却直接决定网卡能否正常工作。放在平台文件里会被 build tag 隔离，
// 导致 Linux 上（开发与 CI 环境）无法测试 Windows/macOS 的命令构造，
// 只能等到真机运行才暴露问题——本次「掩码配成 /16 导致 ping 不通」
// 正是这类只能在真机上才发现的缺陷。
//
// 这里的约定：PlatformCommand 的第一个元素是命令名，其余为参数。

// PlatformCommand 一条待执行的系统命令（命令名 + 参数）。
type PlatformCommand struct {
	Name string
	Args []string
}

// hostMask 网卡地址使用的掩码位数：固定 /32。
//
// 这是本项目的硬性约束，不能改成网段掩码。原因：
// TUN 是三层接口，只收发 IP 报文，不参与 ARP。若网卡配有网段掩码
// （如 10.0.0.2/8），内核会把整个网段视为该接口的直连范围，
// 发往网段内其他主机（如服务器 10.0.0.1）的包会走 ARP 解析链路层地址，
// 而 TUN 永远不会应答 ARP，包也到不了我们的转发逻辑，表现为 ping 永久超时。
//
// 配成 /32 后接口不再「拥有」任何网段，内核只能按路由表转发，
// 命中网段路由后交给 TUN，这才是隧道该走的路径。
const hostMask = 32

// hostMaskString 是 hostMask 的点分十进制形式，供只接受该格式的工具使用。
const hostMaskString = "255.255.255.255"

// validateTunConfig 校验网卡配置入参，三个平台共用。
//
// 不再校验网段：它是 protocol.VNetCIDR 这个编译期常量，
// 为不可变的常量保留运行期校验只是死代码，反而给人「此处可传别的值」的错觉。
func validateTunConfig(ifName, ip string) error {
	if ifName == "" {
		return fmt.Errorf("网卡名为空，无法配置网卡")
	}
	if ip == "" {
		return fmt.Errorf("虚拟 IP 为空，无法配置网卡")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("虚拟 IP %q 格式非法", ip)
	}
	return nil
}

// linuxTunCommands 生成 Linux 的 ip 命令序列。
func linuxTunCommands(ifName, ip string) ([]PlatformCommand, error) {
	if err := validateTunConfig(ifName, ip); err != nil {
		return nil, err
	}
	return []PlatformCommand{
		{"ip", []string{"link", "set", ifName, "up"}},
		// MTU 1420：为 21B 协议头 + 16B GCM tag 预留封装开销，
		// 与 Windows/macOS 保持一致，避免跨平台路径 MTU 不同导致大包被丢。
		{"ip", []string{"link", "set", "dev", ifName, "mtu", "1420"}},
		// /32 地址 + replace（而非 add）：replace 幂等，
		// 重连时地址已存在也不会失败。
		{"ip", []string{"addr", "replace", fmt.Sprintf("%s/%d", ip, hostMask), "dev", ifName}},
		// 网段路由指向固定网段：网段是全网统一的约定，不由配置传入，
		// 从根上杜绝「两端网段不一致 → 路由指向错误网段 → ping 不通」。
		// replace 同样为了幂等。
		{"ip", []string{"route", "replace", protocol.VNetCIDR, "dev", ifName}},
	}, nil
}

// windowsTunCommands 生成 Windows 的 netsh 命令序列。
func windowsTunCommands(ifName, ip string) ([]PlatformCommand, error) {
	if err := validateTunConfig(ifName, ip); err != nil {
		return nil, err
	}
	return []PlatformCommand{
		// 先删后设，保证重连幂等：wintun 网卡在断线时不会同步移除地址，
		// 快速重连（如服务端踢下线后 2 秒重连）时旧地址还挂在网卡上，
		// 此时 netsh set address 对相同地址会报「对象已存在」并使整个连接失败
		// （Linux 用 ip addr replace 幂等，Windows 没有等价命令，只能先删再设）。
		// 地址不在本接口时删除报「找不到元素」，属于无害错误（见 isBenignCommandError）。
		{"netsh", []string{"interface", "ip", "delete", "address",
			"name=" + ifName, ip}},
		// 网卡地址固定 /32，绝不能写成网段掩码（见 hostMask 说明）
		{"netsh", []string{"interface", "ip", "set", "address",
			"name=" + ifName, "static", ip, hostMaskString}},
		// 网段路由：显式给出接口与下一跳。
		// /32 配置下接口没有可依附的 on-link 网段，netsh 要求提供 nexthop；
		// 用自身地址作 nexthop 是安全的——它是接口自己的地址，始终可达。
		{"netsh", []string{"interface", "ip", "add", "route", protocol.VNetCIDR, ifName, ip}},
		// DNS 指向公共解析器：虚拟网内没有 DNS 服务，
		// 留系统默认值会让域名解析走虚拟网卡而超时。
		{"netsh", []string{"interface", "ip", "set", "dns",
			"name=" + ifName, "static", "1.1.1.1", "primary"}},
	}, nil
}

// darwinTunCommands 生成 macOS 的命令序列。
//
// utun 是点对点接口：ifconfig 必须写成
// "ifconfig utunN inet <本端> <对端> netmask ... up"，只给一个地址时
// 系统会把它当作对端地址，本端留空导致网卡不可用。
// 本端与对端都填自身地址——TUN 是单臂接口，不存在真正的链路对端，
// 填自身只是为了让内核接受配置并建立 connected 路由。
func darwinTunCommands(ifName, ip string) ([]PlatformCommand, error) {
	if err := validateTunConfig(ifName, ip); err != nil {
		return nil, err
	}
	return []PlatformCommand{
		{"ifconfig", []string{ifName, "inet", ip, ip, "netmask", hostMaskString, "up"}},
		// 先删后加以实现幂等：route add 遇到已存在路由会报 File exists，
		// 而 delete 不存在的路由只产生无害提示，组合结果始终是「路由存在」。
		{"route", []string{"-n", "delete", "-net", protocol.VNetCIDR}},
		{"route", []string{"-n", "add", "-net", protocol.VNetCIDR, ip}},
	}, nil
}

// isBenignCommandError 判断某个平台命令的报错是否可以忽略。
//
// 判断依据是**报错文本**，不是命令类型。曾经这里按「只要是删除地址/添加路由
// 就直接返回 true」来做——那样一来权限不足、接口名写错这些真故障也会被吞掉：
// 用户没以管理员身份运行，看到的却是一句笼统的「网卡配置失败」，
// 排查方向完全被带偏。删除/添加确实是幂等步骤，但幂等针对的是
// 「目标状态已达成」这一类错误，而不是所有错误。
//
// 只容忍两类「目标状态已达成」：
//   - 删除不存在的地址（Windows 先删后设的第一步）：地址本就不在本接口上，
//     删除只会报「找不到元素」，这正是删除步骤想要的结果。
//     中文版 Windows 的 netsh 输出是 GBK 编码，解码可能失败——解码失败时
//     文本为空，而删除步骤失败本身无害，所以这种情况按无害处理。
//   - 已存在的路由（重连时网段路由往往还在，上次会话未及清理），
//     此时 add 会报错，但路由本身已是我们想要的状态。中文 netsh 的
//     「对象已存在」同样可能因 GBK 解码而丢失，处理方式同上。
//
// 其余错误（权限不足、接口名错误、跨网卡地址冲突等）必须上抛。
func isBenignCommandError(cmd PlatformCommand, out string) bool {
	if isDeleteAddressCommand(cmd) {
		// 删除地址是幂等清理步骤：失败只可能意味着「地址本来就不在」，
		// 而这正是我们想要的终态。解码失败（空串）也归入此类。
		if out == "" {
			return true
		}
		return containsAny(out, missingAddrTexts)
	}
	if isRouteAddCommand(cmd) {
		// 添加路由同理：只在「已存在」时忽略。
		// 注意空输出不算无害——路由没加成功却什么都不报，属于真故障。
		return containsAny(out, routeExistsTexts)
	}
	return false
}

// 各类无害错误的识别文本。
//
// Windows 分中英文两套（netsh 跟随系统语言）；Linux 走 RTNETLINK；
// macOS 的 route 命令报 "File exists"。全部小写后做子串匹配，
// 避免因大小写或语气差异漏判。
var (
	missingAddrTexts = []string{
		"找不到元素",
		"系统找不到指定的元素",
		"cannot find the element",
		"element not found",
	}
	routeExistsTexts = []string{
		"对象已存在",
		"already exists",
		"file exists",
		"file already exists",
		"rtnetlink answers: file exists",
	}
)

// containsAny 报告 s 是否包含 any 中任一片段（忽略大小写）。
func containsAny(s string, any []string) bool {
	low := strings.ToLower(s)
	for _, w := range any {
		if strings.Contains(low, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

// isDeleteAddressCommand 判断命令是否为「删除接口地址」（netsh interface ip delete address）。
func isDeleteAddressCommand(cmd PlatformCommand) bool {
	switch cmd.Name {
	case "netsh":
		// netsh interface ip delete address name=... <ip>
		return len(cmd.Args) >= 4 && cmd.Args[2] == "delete" && cmd.Args[3] == "address"
	default:
		return false
	}
}

// isRouteAddCommand 判断命令是否为「添加路由」。
func isRouteAddCommand(cmd PlatformCommand) bool {
	switch cmd.Name {
	case "netsh":
		// netsh interface ip add route ...
		return len(cmd.Args) >= 4 && cmd.Args[2] == "add" && cmd.Args[3] == "route"
	case "ip":
		// ip route add/replace ...
		return len(cmd.Args) >= 2 && cmd.Args[0] == "route" &&
			(cmd.Args[1] == "add" || cmd.Args[1] == "replace")
	case "route":
		// route -n add -net ...
		return len(cmd.Args) >= 2 && cmd.Args[1] == "add"
	default:
		return false
	}
}

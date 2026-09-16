// Package forward 定义内网穿透规则的格式与解析。
//
// 规则字符串会出现在两个地方：客户端本地配置（config.json 的 forward 数组）
// 与服务端下发的配置（管理页里的一段多行文本）。两边对格式的理解必须完全一致，
// 否则会出现「管理页显示下发成功、客户端却静默忽略」这类只有用户能发现的故障——
// 因此格式与解析只在这里实现一份，服务端校验、客户端执行都走它。
package forward

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// Rule 一条内网穿透规则：把虚拟网络内访问「本机虚拟IP:VPort」的流量，
// DNAT 转发到内网目标 IP:Port。
type Rule struct {
	VPort      uint16
	TargetIP   uint32 // 网络字节序
	TargetPort uint16
}

// String 还原成配置里的写法，用于日志与界面展示。
func (r Rule) String() string {
	return fmt.Sprintf("%d=%s", r.VPort, r.Target())
}

// Target 返回内网目标 "IP:端口"，用于日志与界面展示。
func (r Rule) Target() string {
	return fmt.Sprintf("%s:%d", ipString(r.TargetIP), r.TargetPort)
}

// Parse 解析单条规则，格式为「虚拟端口=内网IP:端口」，例如 8080=192.168.1.5:80。
func Parse(s string) (Rule, error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return Rule{}, fmt.Errorf("规则格式应为 虚拟端口=内网IP:端口: %q", s)
	}
	vport, err := parsePort(strings.TrimSpace(parts[0]))
	if err != nil {
		return Rule{}, fmt.Errorf("虚拟端口无效: %s", parts[0])
	}
	raw := strings.TrimSpace(parts[1])
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return Rule{}, fmt.Errorf("内网目标无效: %s", parts[1])
	}
	ip, err := ip4u32(strings.TrimSpace(host))
	if err != nil {
		return Rule{}, err
	}
	tport, err := parsePort(portStr)
	if err != nil {
		return Rule{}, fmt.Errorf("端口无效: %s", portStr)
	}
	return Rule{VPort: vport, TargetIP: ip, TargetPort: tport}, nil
}

// ParseList 逐条解析规则，任一条失败即整体失败。
//
// 不「跳过坏规则、留下好规则」：一半生效一半静默丢弃的穿透配置，
// 排查成本远高于直接报错让用户改对。
func ParseList(list []string) ([]Rule, error) {
	out := make([]Rule, 0, len(list))
	for _, s := range list {
		r, err := Parse(s)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ParseSet 解析一整组规则，并额外要求虚拟端口互不重复。
//
// 服务端下发前用它校验。重复的虚拟端口在客户端会互相覆盖（规则按端口建索引），
// 结果是「配了两条，只有一条生效」——而且不报任何错。
// 这种问题让管理员对着配置反复核对也看不出，必须在入口拦住。
func ParseSet(list []string) ([]Rule, error) {
	rules, err := ParseList(list)
	if err != nil {
		return nil, err
	}
	seen := make(map[uint16]string, len(rules))
	for _, r := range rules {
		if prev, dup := seen[r.VPort]; dup {
			return nil, fmt.Errorf("虚拟端口 %d 被重复使用：%s 与 %s", r.VPort, prev, r.String())
		}
		seen[r.VPort] = r.String()
	}
	return rules, nil
}

// ParseConfig 解析下发配置里的一条值（可能含多条规则）。
// 空值表示「没有规则」，返回空切片而不是错误。
func ParseConfig(v string) ([]Rule, error) {
	return ParseList(SplitConfig(v))
}

// SplitConfig 把配置值拆成多条规则的字符串。
//
// 分隔符接受换行、逗号、分号与空白：管理页用的是多行文本框，
// 用户可能每行一条，也可能习惯用逗号连写。规则本身不含这些字符，
// 所以宽进无歧义——比要求用户猜「到底该用哪种分隔符」更友好。
func SplitConfig(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || unicode.IsSpace(r)
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// parsePort 解析端口号，限定 1~65535。
//
// 显式拒绝 0：0 在配置里通常意味着「这里没填」，而一条虚拟端口为 0 的规则
// 永远不会被匹配到——留着它只会让用户以为自己配了穿透。
func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("端口需在 1~65535 之间: %q", s)
	}
	return uint16(n), nil
}

// ip4u32 点分十进制 IPv4 转网络字节序。
func ip4u32(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("内网目标不是合法的 IPv4 地址: %q", s)
	}
	return binary.BigEndian.Uint32(ip), nil
}

// ipString 网络字节序转点分十进制。
func ipString(v uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip.String()
}

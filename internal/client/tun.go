package client

// Tun 虚拟网卡抽象：Linux(/dev/net/tun)、Windows(wintun)、macOS(utun)
// 以及测试用的内存模拟网卡都实现该接口。
type Tun interface {
	// Read 读取一个 IP 数据包（内核路由到虚拟网卡的包）。
	Read(buf []byte) (int, error)
	// Write 写入一个 IP 数据包（进入内核网络栈）。
	Write(buf []byte) (int, error)
	// Configure 配置虚拟 IP 与固定网段路由。
	//
	// 注意：各平台实现都应当给网卡配 ip/32（而非网段掩码）并单独添加网段路由。
	// 配成网段掩码会让内核把整段视为「直连」，从而对跨主机流量发 ARP 而不走本接口，
	// 而 TUN 不响应 ARP，最终表现为「已上线但 ping 不通」。
	// 详见 tun_config.go 中 hostMask 的说明。
	//
	// 网段不是入参：它由 protocol.VNetCIDR 全网统一约定，
	// 避免两端各自配置导致不一致。
	Configure(ip string) error
	// Close 关闭网卡。
	Close() error
	// Name 返回接口名。
	Name() string
}

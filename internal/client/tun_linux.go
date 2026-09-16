//go:build linux

package client

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// TunDevice 基于 Linux /dev/net/tun 的虚拟网卡（三层 TUN，无 PI 头）。
type TunDevice struct {
	fd   int
	name string
}

const (
	tunDevice = "/dev/net/tun"
	ifnamsiz  = 16
	tunSetIff = 0x400454ca // TUNSETIFF
	iffTun    = 0x0001
	iffNoPI   = 0x1000
)

type ifreq struct {
	name  [ifnamsiz]byte
	flags uint16
	pad   [22]byte
}

// OpenTun 打开并创建一块 TUN 虚拟网卡，name 为 0-15 字符的接口名（留空自动分配）。
func OpenTun(name string) (*TunDevice, error) {
	fd, err := syscall.Open(tunDevice, syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w（需要 root 或 CAP_NET_ADMIN）", tunDevice, err)
	}
	var ifr ifreq
	copy(ifr.name[:], name)
	ifr.flags = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	ifName := string(ifr.name[:])
	// 截断到首个 NUL
	for i, c := range ifName {
		if c == 0 {
			ifName = ifName[:i]
			break
		}
	}
	return &TunDevice{fd: fd, name: ifName}, nil
}

// Configure 配置虚拟 IP、MTU 和固定网段路由。
//
// 命令构造见 tun_config.go 的 linuxTunCommands——
// 网卡只配 ip/32 而非网段掩码，原因在 hostMask 的注释里有完整说明。
// Linux 下网段掩码还多一层危害：内核会据此生成 scope=link 的直连路由，
// 优先级高于我们添加的路由，跨主机包因此被导向 ARP 而非本接口。
func (t *TunDevice) Configure(ip string) error {
	cmds, err := linuxTunCommands(t.name, ip)
	if err != nil {
		return err
	}
	for _, c := range cmds {
		out, err := exec.Command(c.Name, c.Args...).CombinedOutput()
		if err != nil {
			if isBenignCommandError(c, string(out)) {
				continue
			}
			return fmt.Errorf("%s %s: %s", c.Name, strings.Join(c.Args, " "), out)
		}
	}
	return nil
}

// Read 读取一个 IP 数据包（带 MTU 上限的缓冲）。
func (t *TunDevice) Read(buf []byte) (int, error) {
	return syscall.Read(t.fd, buf)
}

// Write 写入一个 IP 数据包。
func (t *TunDevice) Write(buf []byte) (int, error) {
	return syscall.Write(t.fd, buf)
}

// Close 关闭虚拟网卡。
func (t *TunDevice) Close() error {
	return syscall.Close(t.fd)
}

// Name 返回接口名。
func (t *TunDevice) Name() string { return t.name }

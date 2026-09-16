//go:build darwin

// macOS TUN 实现：使用系统 utun（通过 golang.zx2c4.com/wireguard/tun）。
// 需要 root 权限（sudo）启动。
package client

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

// TunDevice 基于 utun 的虚拟网卡。
// wireguard/tun 为批量读写接口，此处适配为项目内部的单包语义。
type TunDevice struct {
	dev  tun.Device
	name string
}

// OpenTun 创建一块 utun 虚拟网卡。
func OpenTun(name string) (*TunDevice, error) {
	dev, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return nil, fmt.Errorf("创建 utun 失败（需要 sudo 权限）: %w", err)
	}
	actual, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("获取网卡名失败: %w", err)
	}
	return &TunDevice{dev: dev, name: actual}, nil
}

// Configure 配置虚拟 IP 与固定网段路由。
//
// 命令构造见 tun_config.go 的 darwinTunCommands——
// 网卡只配 /32，原因在 hostMask 的注释里有完整说明；
// utun 的点对点语法细节见 darwinTunCommands 的注释。
func (t *TunDevice) Configure(ip string) error {
	cmds, err := darwinTunCommands(t.name, ip)
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

// Read 读取一个 IP 数据包（单包语义包装批量接口）。
func (t *TunDevice) Read(buf []byte) (int, error) {
	bufs := [][]byte{buf}
	sizes := []int{0}
	n, err := t.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

// Write 写入一个 IP 数据包。
func (t *TunDevice) Write(buf []byte) (int, error) {
	_, err := t.dev.Write([][]byte{buf}, 0)
	if err != nil {
		return 0, err
	}
	return len(buf), nil
}

// Close 关闭虚拟网卡。
func (t *TunDevice) Close() error {
	return t.dev.Close()
}

// Name 返回接口名。
func (t *TunDevice) Name() string { return t.name }

//go:build windows

// Windows TUN 实现：基于 wintun 驱动（通过 golang.zx2c4.com/wireguard/tun）。
//
// 开箱即用设计：
//   - wintun.dll 由本程序内嵌并在启动时释放到 %APPDATA%\SulinkLan（见 wintun_embed.go），
//     用户无需手动下载放置 dll；
//   - 创建虚拟网卡需要管理员权限，打包时已通过 manifest 声明 UAC 提权。
package client

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"golang.zx2c4.com/wireguard/tun"
)

// hideConsoleWindow 让子进程不弹出控制台窗口（GUI 模式下避免闪黑窗）。
func hideConsoleWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}

// TunDevice 基于 wintun 的虚拟网卡。
// wireguard/tun 的 Device 接口为批量读写（[][]byte），此处适配为
// 项目内部使用的单包读写语义（Tun 接口）。
type TunDevice struct {
	dev  tun.Device
	name string
}

// OpenTun 创建一块 wintun 虚拟网卡。
// 调用前应确保 EnsureWintunDLL() 已成功执行（main 中统一处理）。
func OpenTun(name string) (*TunDevice, error) {
	if name == "" {
		name = "Sulink Lan"
	}
	// 先清理历史残留的同名/带序号网卡，确保新建的网卡固定叫 name（不带 " 109" 这类序号）。
	removeStaleSulinkAdapters(name)
	dev, err := tun.CreateTUN(name, 1420)
	if err != nil {
		return nil, fmt.Errorf("创建虚拟网卡失败（需要管理员权限）: %w", err)
	}
	actual, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("获取网卡名失败: %w", err)
	}
	return &TunDevice{dev: dev, name: actual}, nil
}

// Configure 配置虚拟 IP 与固定网段路由。
// 使用 netsh 而非 PowerShell：兼容性更好、启动更快，且无需执行策略配置。
//
// 命令构造见 tun_config.go 的 windowsTunCommands——
// 网卡只配 ip/32 而非网段掩码，原因在 hostMask 的注释里有完整说明。
func (t *TunDevice) Configure(ip string) error {
	cmds, err := windowsTunCommands(t.name, ip)
	if err != nil {
		return err
	}
	for _, c := range cmds {
		cmd := exec.Command(c.Name, c.Args...)
		// 隐藏 netsh 等控制台子进程窗口，避免 GUI 连接时弹出黑色控制台。
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := cmd.CombinedOutput()
		// netsh 在中文 Windows 上输出 GBK 编码，直接按 UTF-8 匹配中文字符串会失败。
		// 解码成 UTF-8 后再判断是否为无害错误（ASCII 在两种编码下一致，不影响英文系统）。
		outStr := decodeNetshOutput(out)
		if err != nil {
			if isBenignCommandError(c, outStr) {
				continue
			}
			return fmt.Errorf("配置网卡失败（%s %s）: %s",
				c.Name, strings.Join(c.Args, " "), outStr)
		}
	}
	return nil
}

// decodeNetshOutput 把 netsh 子进程输出解码为 UTF-8。
//
// 为什么不能"看到中文就按 GBK 解"：这个假设在真机上被证伪过。
// 曾经这里只在输出含高位字节（非 ASCII）时就用 GBK 强解，理由是
// 「中文 Windows 的 netsh 输出是 GBK」——但 Windows 10/11 的 netsh
// 实际输出的是 **UTF-8**（实测：删除不存在的接口地址，
// 输出字节 e69687 e4bbb6… 按 UTF-8 读正是「文件名、目录名或卷标语法不正确。」）。
// 把正确的 UTF-8 当 GBK 解，只会得到一串乱码，
// 于是「找不到元素」「对象已存在」这些中文关键字全部匹配不上，
// 无害的幂等错误被当成真故障上抛，表现为连接莫名失败——
// 且这些错误只出现在中文系统上，排查时极易被当成网络问题。
//
// 正确顺序是**先信 UTF-8**：合法 UTF-8 就直接用。这不是猜测——
// GBK 编码的中文（如「找不到元素」= d5d2 b2bb b5bd d4aa cbd8）
// 几乎不可能是合法 UTF-8 序列，两者可以可靠区分。
// 只有 UTF-8 校验失败时才回退 GBK，兼容真正输出 GBK 的老系统。
//
// 纯 ASCII 输出在两种编码下一致，因此英文 Windows 完全不受影响。
func decodeNetshOutput(b []byte) string {
	// 快路径：纯 ASCII 无需解码。
	ascii := true
	for _, c := range b {
		if c > 127 {
			ascii = false
			break
		}
	}
	if ascii {
		return string(b)
	}
	// 优先按 UTF-8：现代 Windows 的 netsh 就是 UTF-8。
	if utf8.Valid(b) {
		return string(b)
	}
	// 回退 GBK：老系统或某些被重定向的输出。
	if decoded, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), b); err == nil {
		return string(decoded)
	}
	// 两种都解不出（极端情况，如半截多字节被截断）：
	// 原样返回，让调用方按英文/空串逻辑处理。
	return string(b)
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

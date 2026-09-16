// 服务端入口：信令 + 虚拟IP分配 + 打洞协助 + UDP中继。
//
// 认证：无需预共享密钥、无需注册码。客户端打开软件时凭本机设备标识
// （HWID）自动注册，服务端为每台设备签发/复用长期凭证（见
// internal/server/server.go 的 handleRegister）。设备表与凭证随租约落盘。
//
// 用法：
//
//	./sulink-lan-server                          # 默认监听 0.0.0.0:9000
//	./sulink-lan-server -addr 0.0.0.0:9000
//
// 两份状态会落盘（路径见 -lease-file / -config-file，启动日志里也会打印）：
// 设备表保存 IP 租约、设备凭证与每台设备的穿透规则，全局配置保存公告与禁止打洞开关。
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"sulink-lan/internal/admin"
	"sulink-lan/internal/npsembed"
	"sulink-lan/internal/prompt"
	"sulink-lan/internal/server"
)

// envAdminToken 管理页令牌的环境变量名。容器里推荐用这个传，
// 避免令牌出现在 docker inspect 的命令行参数里。
const envAdminToken = "SULINK_ADMIN_TOKEN"

// adminOff 表示关闭管理页的特殊取值。
const adminOff = "off"

func main() {
	addr := flag.String("addr", "0.0.0.0:9000", "信令 TCP + 中继 UDP 监听地址")
	adminAddr := flag.String("admin", "127.0.0.1:8080",
		"Web 管理页监听地址；填 off 关闭。默认只监听本机，暴露到公网前请自行加 HTTPS 反向代理")
	adminToken := flag.String("admin-token", "", "Web 管理页访问令牌（不填则自动生成并打印到日志）")
	leaseFile := flag.String("lease-file", "sulink-devices.json",
		"设备表落盘路径（IP 租约 + 设备凭证 + 每台设备的穿透规则）；留空表示不落盘，重启后租约与规则丢失")
	configFile := flag.String("config-file", "sulink-server-config.json",
		"全局配置落盘路径（公告 / 禁止打洞）；留空表示不落盘，重启后公告丢失")
	npsDataDir := flag.String("nps-data", "nps-data",
		"内嵌 NPS 服务端的数据目录（保存 NPS 自己的配置/客户端/隧道）；留空则不启动 NPS")
	flag.Parse()

	srv, err := server.New(server.Config{
		TCPAddr:    *addr,
		UDPAddr:    *addr,
		LeaseFile:  *leaseFile,
		ConfigFile: *configFile,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] 初始化失败: %v\n", err)
		prompt.PauseIfDoubleClick()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 管理页与信令服务并行运行：两者互不依赖，任何一个挂掉都应让整个进程退出，
	// 否则会出现「信令在跑但管理页 502」这种只报一半故障的状态。
	errCh := make(chan error, 2)
	go func() { errCh <- srv.Run(ctx) }()

	if adm := startAdmin(*adminAddr, *adminToken, srv); adm != nil {
		go func() { errCh <- adm.Run(ctx) }()
	}

	if *npsDataDir != "" {
		srv.OnDeviceOnline = func(vkey, name, vip string) {
			if err := npsembed.EnsureClientByVkey(vkey, name); err != nil {
				fmt.Fprintf(os.Stderr, "[nps] 自动注册 NPC 客户端失败: %v\n", err)
			}
		}
		go func() {
			lister := func() []npsembed.DeviceInfo {
				snap := srv.Snapshot()
				out := make([]npsembed.DeviceInfo, 0, len(snap.Devices))
				for _, d := range snap.Devices {
					out = append(out, npsembed.DeviceInfo{
						Hwid: d.HWID,
						Name: d.Name,
						VIP:  d.VIP,
					})
				}
				return out
			}
			if wp, err := npsembed.StartWithDevices(*npsDataDir, lister); err != nil {
				fmt.Fprintf(os.Stderr, "[server] NPS 启动失败: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[server] NPS 管理面板: http://127.0.0.1:%d  (默认用户名 admin，密码见 nps-data/conf/nps.conf)\n", wp)
			}
		}()
	}

	if err := <-errCh; err != nil {
		fmt.Fprintf(os.Stderr, "[server] 启动失败: %v\n", err)
		prompt.PauseIfDoubleClick()
		os.Exit(1)
	}
}

// startAdmin 按配置创建管理页服务；返回 nil 表示不启用。
//
// 令牌来源优先级：命令行参数 > 环境变量 > 自动生成。
// 自动生成是为了「默认安全」：绝大多数用户不会主动设令牌，
// 若默认空令牌就等于默认无鉴权。生成后打印到日志，用户复制即可。
func startAdmin(addr, token string, ctl admin.Control) *admin.Server {
	if strings.TrimSpace(addr) == "" || strings.EqualFold(strings.TrimSpace(addr), adminOff) {
		fmt.Fprintln(os.Stderr, "[server] Web 管理页已关闭")
		return nil
	}
	if token == "" {
		token = os.Getenv(envAdminToken)
	}
	generated := false
	if token == "" {
		t, err := randomToken()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] 生成管理令牌失败，管理页未启动: %v\n", err)
			return nil
		}
		token, generated = t, true
	}

	adm, err := admin.New(admin.Config{Addr: addr, Token: token}, ctl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] 管理页初始化失败: %v\n", err)
		return nil
	}
	if generated {
		// 打印到 stderr 而非日志文件：这是用户此刻就需要复制的一次性信息
		fmt.Fprintf(os.Stderr, "[server] 管理令牌自动生成: %s\n", token)
		fmt.Fprintf(os.Stderr, "[server] 固定令牌请用 -admin-token 或环境变量 %s\n\n", envAdminToken)
	} else {
		fmt.Fprintf(os.Stderr, "[server] 管理令牌：使用你指定的令牌（不随重启变化）\n\n")
	}
	return adm
}

// randomToken 生成 24 字节的随机令牌（base64url，约 32 字符）。
//
// 24 字节 = 192 位熵，暴力枚举不可行；URL 安全字符集，
// 复制粘贴到浏览器不会因 + / = 被转义。
func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// 命令行客户端入口：虚拟网卡 + P2P 打洞 + 服务器中转 + 内网穿透。
//
// 适用于：无图形界面的环境（服务器、脚本化调用），或需要精细控制参数的场景。
// 普通用户请使用图形客户端 sulink-lan-client.exe。
//
// 用法（无需任何密钥/注册码，打开即按本机设备标识自动注册）：
//
//	sulink-lan-cli.exe -server 服务器IP:9000 -name 你的设备名
//
// 首次连接自动注册，设备凭证保存到凭证文件
// （默认 %APPDATA%\SulinkLan\cli-credentials.json），之后直接运行即可。
// 重装系统/删除凭证文件后再次运行，会自动找回或重签凭证，无需手工操作。
//
// 内网穿透规则不在此处配置：它由服务端按设备标识下发（管理页维护），
// 客户端只负责执行，见 internal/client/rules.go。
//
// Windows 上需要以管理员权限运行（创建虚拟网卡）。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"sulink-lan/internal/client"
)

// cliCred 命令行客户端的凭证持久化形态（自动注册签发）。
type cliCred struct {
	DeviceID   string `json:"device_id"`
	DeviceKey  string `json:"device_key"`
	NetworkKey string `json:"network_key"`
}

// defaultCredFile 凭证文件默认路径：~/.config/sulink-lan/credentials.json
// （Windows 下为 %APPDATA%\SulinkLan\cli-credentials.json，与 GUI 的
// config.json 分开，互不覆盖）。
func defaultCredFile() string {
	base := os.Getenv("APPDATA")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		} else {
			base = os.TempDir()
		}
	}
	return filepath.Join(base, "SulinkLan", "cli-credentials.json")
}

// loadCred 读取凭证文件；文件不存在返回 nil（不报错，连接时自动注册）。
func loadCred(path string) (*cliCred, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c cliCred
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("凭证文件损坏: %w", err)
	}
	return &c, nil
}

// saveCred 原子写入凭证文件（0600：内容等同设备身份）。
func saveCred(path string, c *cliCred) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func main() {
	server := flag.String("server", "", "信令服务器地址 host:port（必填）")
	devid := flag.String("devid", "", "设备凭证 ID（通常从凭证文件自动加载，可省略）")
	devkey := flag.String("devkey", "", "设备密钥（通常从凭证文件自动加载，可省略）")
	netkey := flag.String("netkey", "", "网络密钥（通常从凭证文件自动加载，可省略）")
	credFile := flag.String("cred-file", defaultCredFile(), "设备凭证文件路径（自动保存/加载）")
	name := flag.String("name", "", "本机设备名（必填，同一服务器内唯一）")
	nopunch := flag.Bool("nopunch", false, "禁用 P2P 打洞，强制走服务器中转")
	flag.Parse()

	if *server == "" || *name == "" {
		flag.Usage()
		os.Exit(1)
	}

	// 凭证自动加载：没有 -devkey 直传时读取凭证文件。文件不存在也没关系——
	// 打开软件即按本机设备标识自动注册，注册成功后凭证会写回该文件。
	if *devkey == "" {
		if cred, err := loadCred(*credFile); err != nil {
			log.Fatalf("[client] 读取凭证文件失败: %v", err)
		} else if cred != nil && cred.DeviceKey != "" {
			*devid, *devkey, *netkey = cred.DeviceID, cred.DeviceKey, cred.NetworkKey
			log.Printf("[client] 已从凭证文件加载设备凭证（%s）", shortID(cred.DeviceID))
		} else {
			log.Printf("[client] 无本地凭证，连接时自动注册（按本机设备标识）")
		}
	}

	// Windows 下需要 wintun.dll：从内嵌资源释放到 exe 同目录
	cleanup, err := client.PreparePlatform()
	if err != nil {
		log.Fatalf("[client] 运行环境准备失败: %v", err)
	}
	defer cleanup()

	c := client.NewClient(client.Config{
		Server:     *server,
		Name:       *name,
		NoPunch:    *nopunch,
		DeviceID:   *devid,
		DeviceKey:  *devkey,
		NetworkKey: *netkey,
		// 注册成功：凭证落盘，下次直接运行即可
		OnCredential: func(deviceID, deviceKey, networkKey string) error {
			if err := saveCred(*credFile, &cliCred{DeviceID: deviceID, DeviceKey: deviceKey, NetworkKey: networkKey}); err != nil {
				return err
			}
			log.Printf("[client] 设备凭证已保存到 %s，之后直接运行即可", *credFile)
			return nil
		},
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Printf("[client] 退出中…")
		c.Close()
	}()

	if err := c.Run(); err != nil {
		log.Fatalf("[client] %v", err)
	}
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

// Package config 客户端配置的持久化。
//
// 配置文件位置（Windows）：
//
//	%APPDATA%\SulinkLan\config.json
//
// 采用「字段缺失即用默认值」的宽松解析，保证旧版本配置文件升级后仍可用。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Config 客户端配置。字段带 json tag，便于人工编辑与版本演进。
//
// 这里**没有**内网穿透规则字段：穿透规则由服务端按设备标识统一下发
// （见 protocol.MsgForwardPush）。早期版本允许在客户端本地配置 forward，
// 但那样「哪台机器该暴露哪个内网服务」就散落在每台机器的配置文件里，
// 管理员既看不到全貌，也无法在设备离线时预先配置，改一台要远程连一台。
// 现在客户端只负责执行，配置入口只有服务端管理页一处。
//
// 旧配置文件里遗留的 forward / forward_on 键会被宽松忽略（未知字段不报错），
// 不需要迁移，但保存后不再写出。
type Config struct {
	Server      string `json:"server"`       // 信令服务器地址 host:port
	Name        string `json:"name"`         // 本机设备名
	NoPunch     bool   `json:"no_punch"`     // 禁用 P2P 打洞
	AutoConnect bool   `json:"auto_connect"` // 启动后自动连接
	AutoStart   bool   `json:"auto_start"`   // 开机自启
	// 设备凭证：客户端打开软件时按本机设备标识（HWID）自动注册，服务端签发后
	// 写入本配置；之后每次连接用它认证。三个字段同时为空表示尚未注册，
	// 连接时自动走注册流程（重装系统/删除配置后会自动找回或重签凭证）。
	DeviceID   string `json:"device_id,omitempty"`   // 设备凭证 ID
	DeviceKey  string `json:"device_key,omitempty"`  // 设备密钥（hex）
	NetworkKey string `json:"network_key,omitempty"` // 数据面网络密钥（hex）
}

// Default 返回默认配置。
//
// 虚拟网段不在此处：它由 protocol.VNetCIDR 全网统一约定（固定 10.0.0.0/8），
// 不属于用户可配置项——两端各配各的曾导致「已上线但 ping 不通」的疑难故障。
func Default() Config {
	host, _ := os.Hostname()
	if host == "" {
		host = "我的电脑"
	}
	return Config{
		Server:      DefaultServerAddr,
		Name:        host,
		AutoConnect: false,
		AutoStart:   false,
	}
}

// Dir 返回配置目录（%APPDATA%\SulinkLan），不存在则创建。
func Dir() (string, error) {
	base := os.Getenv("APPDATA")
	if base == "" {
		// 非 Windows 或环境异常时的回退
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		} else {
			base = os.TempDir()
		}
	}
	dir := filepath.Join(base, "SulinkLan")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建配置目录失败: %w", err)
	}
	return dir, nil
}

// Path 返回配置文件完整路径。
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load 读取配置。文件不存在时返回默认配置（不报错，保证首启可用）。
func Load() (Config, error) {
	cfg := Default()
	path, err := Path()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil // 首次运行
	}
	if err != nil {
		return cfg, err
	}
	// 宽松解析：未知字段忽略，缺失字段保持默认值。
	// 旧版本配置里的 "cidr" 字段由此被自动忽略，无需迁移。
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Default(), fmt.Errorf("配置文件格式错误: %w", err)
	}
	// 老配置或手动改空后，Server 可能被 Unmarshal 覆盖成空串。
	// 这里兜底：空就用默认地址，避免首启/老配置点连接直接报「server 不能为空」。
	if strings.TrimSpace(cfg.Server) == "" {
		cfg.Server = DefaultServerAddr
	}
	return cfg, nil
}

// Save 写入配置（先写临时文件再改名，避免写坏原文件）。
func (c Config) Save() error {
	path, err := Path()
	if err != nil {
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

// Validate 校验必填项，返回面向用户的错误说明。
//
// 认证无需任何手工凭证：客户端打开软件即按本机设备标识自动注册，
// 只需服务器地址与设备名。
func (c Config) Validate() error {
	if strings.TrimSpace(c.Server) == "" {
		c.Server = DefaultServerAddr
	}
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("请填写设备名")
	}
	return nil
}

// DefaultServerAddr 用户没填服务器地址时使用的默认地址。
const DefaultServerAddr = "lan.sulink.ltd"

// DefaultServerPort 用户只填 IP 不填端口时使用的默认端口。
const DefaultServerPort = "9000"

// NormalizeServerAddr 规范化服务器地址：只填 host（不含端口）时补 :9000。
//
// 例如 "1.2.3.4" -> "1.2.3.4:9000"；"1.2.3.4:8080" 保持不变；
// IPv6 形如 "::1" 会被补成 "[::1]:9000"（用方括号包住）。
// 空串原样返回。
func NormalizeServerAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	// 已经带端口（含冒号）就不动。注意 IPv6 地址本身含多个冒号，
	// 只要出现过冒号就认为用户已自行指定端口或就是 IPv6 字面量。
	if strings.Contains(addr, ":") {
		return addr
	}
	return net.JoinHostPort(addr, DefaultServerPort)
}

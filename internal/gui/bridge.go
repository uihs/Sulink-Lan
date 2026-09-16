//go:build windows

// 前后端桥接：前端通过 JSON 字符串调用这里的 Go 方法。
//
// 为什么用 JSON 字符串而不是结构化参数：
// go-webview2 的 Bind 把 Go 函数包装成 JS 全局函数，返回值经 JSON 序列化回传。
// 返回 string（JSON 文本）比依赖结构体自动编解码更稳定，也避免在前端
// 处理 Go 特有的字段大小写问题。
package gui

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"sulink-lan/internal/client"
	"sulink-lan/internal/config"
	"sulink-lan/internal/protocol"
)

// reply 统一响应结构：{ok:true, data:...} 或 {ok:false, error:"..."}。
type reply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func ok() string {
	b, _ := json.Marshal(reply{OK: true})
	return string(b)
}

func fail(format string, args ...any) string {
	b, _ := json.Marshal(reply{Error: fmt.Sprintf(format, args...)})
	return string(b)
}

// SaveConfig 保存配置。入参为表单 JSON。
func (a *App) SaveConfig(payload string) string {
	var in config.Config
	if err := json.Unmarshal([]byte(payload), &in); err != nil {
		return fail("参数格式错误")
	}

	a.mu.Lock()
	cur := a.cfg
	a.mu.Unlock()

	// 空值沿用原值：表单部分字段（如设备名）可能未提交
	if in.Name == "" {
		in.Name = cur.Name
	}

	// 校验仅针对真正需要的字段：允许先保存半成品配置，连接时再报错
	if err := validatePartial(in); err != nil {
		return fail("%s", err.Error())
	}

	a.mu.Lock()
	a.cfg = in
	a.mu.Unlock()

	if err := in.Save(); err != nil {
		return fail("保存失败: %s", err.Error())
	}
	a.logEvent("设置已保存")
	return ok()
}

// Connect 启动客户端连接。立即返回，实际状态由前端轮询 GetStateJSON 获取。
func (a *App) Connect() string {
	a.mu.Lock()
	if a.cli != nil {
		a.mu.Unlock()
		return ok() // 已在连接中，幂等
	}
	cfg := a.cfg
	a.mu.Unlock()

	if err := cfg.Validate(); err != nil {
		a.setStatus("error", err.Error())
		a.logEvent("连接失败：%s", err.Error())
		return fail("%s", err.Error())
	}

	// 穿透规则不在这里传入：它由服务端按设备标识下发，
	// 客户端在注册完成后主动查询（见 internal/client/rules.go）。
	c := client.NewClient(client.Config{
		Server:     cfg.Server,
		Name:       cfg.Name,
		NoPunch:    cfg.NoPunch,
		MTU:        1420,
		DeviceID:   cfg.DeviceID,
		DeviceKey:  cfg.DeviceKey,
		NetworkKey: cfg.NetworkKey,
		// 注册成功回调：把服务端签发的凭证持久化到 config.json，
		// 下次启动直接凭凭证连接，无需任何手工输入。
		OnCredential: func(deviceID, deviceKey, networkKey string) error {
			a.mu.Lock()
			a.cfg.DeviceID, a.cfg.DeviceKey, a.cfg.NetworkKey = deviceID, deviceKey, networkKey
			err := a.cfg.Save()
			a.mu.Unlock()
			return err
		},
	})
	// 虚拟网段由 protocol.VNetCIDR 统一约定，无需注入网段纠正回调。

	a.mu.Lock()
	a.cli = c
	a.state.Status = "connecting"
	a.state.Message = "正在连接…"
	a.state.IP = ""
	a.state.Transport = ""
	a.state.Latency = 0
	stop := make(chan struct{})
	a.stop = stop
	a.mu.Unlock()

	a.logEvent("正在连接")
	go a.runClient(c, stop)

	return ok()
}

// runClient 在后台运行客户端并同步状态到界面。
//
// client.Run 内部自带断线重连（阻塞式），因此这里只跑一次；
// 停止时通过 Close 关闭客户端，Run 随之返回。
func (a *App) runClient(c *client.Client, stop chan struct{}) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := c.Run(); err != nil {
			a.setStatus("error", err.Error())
			a.logEvent("连接失败：%s", err.Error())
		}
	}()

	// 轮询客户端状态（IP / 传输方式），直到连接结束
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			c.Close()
			a.npc.stop()
			<-done
			a.mu.Lock()
			a.cli = nil
			a.mu.Unlock()
			a.setStatus("disconnected", "未连接")
			a.logEvent("已断开")
			return
		case <-done:
			// Run 返回：要么致命错误，要么被 Close
			a.npc.stop()
			a.mu.Lock()
			wasConnecting := a.cli == c
			if wasConnecting {
				a.cli = nil
			}
			a.mu.Unlock()
			if wasConnecting {
				a.mu.Lock()
				st := a.state.Status
				a.mu.Unlock()
				if st == "connected" || st == "connecting" {
					a.setStatus("disconnected", "未连接")
				}
			}
			return
		case <-ticker.C:
			a.syncFromClient(c)
		}
	}
}

// syncFromClient 从客户端读取实时状态写入界面快照。
func (a *App) syncFromClient(c *client.Client) {
	notice := c.Notice()
	pushed := c.PushedConfig()
	lease := c.LeaseUntil()
	a.mu.Lock()
	noticeChanged := a.state.Notice != notice
	a.state.Notice = notice
	a.state.Pushed = pushed
	a.state.LeaseUntil = lease
	a.mu.Unlock()
	if noticeChanged {
		if notice == "" {
			a.logEvent("服务端公告已清除")
		} else {
			a.logEvent("接收到服务器信息")
		}
	}

	// 从服务端拉取本设备的 NPS 隧道列表
	a.fetchTunnels()

	vip := c.SelfVIP()
	if vip == 0 {
		return
	}
	ip := protocol.IP4String(vip)
	a.mu.Lock()
	changed := a.state.IP != ip || a.state.Status != "connected"
	a.state.IP = ip
	a.mu.Unlock()

	if changed {
		a.setStatus("connected", "")
		a.logEvent("已连接，虚拟地址 %s", ip)
		// 连接成功后启动内嵌 NPS NPC（此时已有 device_key）
		a.mu.Lock()
		dk := a.cfg.DeviceKey
		srv := a.cfg.Server
		a.mu.Unlock()
		log.Printf("[gui] 启动 NPC: server=%s, deviceKey=%s", srv, func() string {
			if dk == "" { return "(空)" }
			if len(dk) > 8 { return dk[:8] + "..." }
			return dk
		}())
		a.npc.start(srv, dk)
	}

	// 传输方式：任一对端打通即显示直连，否则中转
	direct, total := c.PeerStats()
	a.mu.Lock()
	switch {
	case total == 0:
		a.state.Transport = ""
	case direct > 0:
		a.state.Transport = "direct"
	default:
		a.state.Transport = "relay"
	}
	a.mu.Unlock()
}

// Disconnect 主动断开连接。
func (a *App) Disconnect() string {
	a.mu.Lock()
	stop := a.stop
	a.mu.Unlock()
	if stop == nil {
		return ok()
	}
	a.setStatus("connecting", "正在断开…")
	select {
	case <-stop:
		// 已经关闭过（幂等）
	default:
		close(stop)
	}
	return ok()
}

// SetAutoStart 设置开机自启（写注册表 Run 项）。
func (a *App) SetAutoStart(on bool) string {
	if err := setAutoStart(on); err != nil {
		return fail("设置开机自启失败：%s", err.Error())
	}
	a.mu.Lock()
	a.cfg.AutoStart = on
	cfg := a.cfg
	a.mu.Unlock()
	if err := cfg.Save(); err != nil {
		return fail("保存失败：%s", err.Error())
	}
	if on {
		a.logEvent("已开启开机自启")
	} else {
		a.logEvent("已关闭开机自启")
	}
	return ok()
}

// ClearLogs 清空事件日志。
func (a *App) ClearLogs() string {
	a.mu.Lock()
	a.state.Logs = []string{}
	a.mu.Unlock()
	return ok()
}

// IsConnected 返回当前是否处于已连接状态。
func (a *App) IsConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.Status == "connected"
}

// statusOrDefault 返回当前状态，空则按断开处理。
func (a *App) statusOrDefault() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Status == "" {
		return "disconnected"
	}
	return a.state.Status
}

// fetchTunnels 从服务端拉取本设备的 NPS 隧道列表。
// 用 device_key 认证，不需要 admin token。
func (a *App) fetchTunnels() {
	a.mu.Lock()
	dk := a.cfg.DeviceKey
	srv := a.cfg.Server
	a.mu.Unlock()
	if dk == "" {
		return
	}
	// 服务器地址可能不带端口，补全后取 host
	normalized := config.NormalizeServerAddr(srv)
	host, _, err := net.SplitHostPort(normalized)
	if err != nil {
		return
	}
	// 管理面板在 8080 端口
	url := fmt.Sprintf("http://%s/api/sulink/my-tunnels?device_key=%s",
		net.JoinHostPort(host, "8080"), dk)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var result struct {
		OK    bool `json:"ok"`
		Items []TunnelView `json:"items"`
	}
	if err := json.Unmarshal(body, &result); err != nil || !result.OK {
		return
	}
	a.mu.Lock()
	a.state.Tunnels = result.Items
	a.mu.Unlock()
}

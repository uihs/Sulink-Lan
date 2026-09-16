//go:build windows

package gui

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"sulink-lan/internal/client"
	"sulink-lan/internal/config"

	webview "github.com/jchv/go-webview2"
)

// App GUI 应用状态。
type App struct {
	w   webview.WebView
	mu  sync.Mutex
	cfg config.Config

	cli  *client.Client // 当前运行的客户端实例（nil 表示未连接）
	stop chan struct{}  // 通知连接协程退出（nil 表示未连接）

	// npc 内嵌 NPS NPC 客户端（公网访问用）
	npc *npcManager

	state State
}

// Run 启动 GUI 主循环（阻塞至窗口关闭）。
func Run() error {
	runtime.LockOSThread()
	return RunWithOptions(Options{})
}

// New 创建 GUI 应用（加载配置）。
func New() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
		log.Printf("[gui] 配置加载失败，使用默认配置: %v", err)
	}
	a := &App{
		cfg:   cfg,
		npc:   newNpcManager(),
		state: State{Status: "disconnected", Message: "未连接", Logs: []string{}},
	}
	a.state.Config = a.publicConfig()
	return a, nil
}

// GetStateJSON 返回状态快照。
func (a *App) GetStateJSON() string {
	a.mu.Lock()
	s := a.state
	s.Config = a.publicConfig()
	s.Logs = append([]string(nil), a.state.Logs...)
	connected := a.cli != nil
	a.mu.Unlock()

	s.Version = appVersion
	s.Protocol = protocolVersion
	s.Busy = connected
	s.Elevated = IsElevated()

	data, _ := json.Marshal(s)
	return string(data)
}

func (a *App) publicConfig() config.Config {
	return a.cfg
}

// CopyText 由前端请求把文本写入系统剪贴板。
func (a *App) CopyText(text string) string {
	if a.w != nil {
		a.w.Dispatch(func() {
			a.w.Eval("navigator.clipboard.writeText(" + jsQuote(text) + ")")
		})
	}
	return ok()
}

// Quit 关闭应用（先断开连接再退出）。
func (a *App) Quit() string {
	a.Disconnect()
	if a.w != nil {
		a.w.Terminate()
	}
	return ok()
}

// logEvent 追加一条事件日志（保留最近 100 条）。
func (a *App) logEvent(format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format("15:04:05")
	a.state.Logs = append([]string{ts + "  " + msg}, a.state.Logs...)
	if len(a.state.Logs) > 100 {
		a.state.Logs = a.state.Logs[:100]
	}
}

// setStatus 更新状态字段。
func (a *App) setStatus(status, message string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.Status = status
	a.state.Message = message
	if status == "connecting" {
		a.state.IP = ""
	}
	if status == "disconnected" || status == "error" {
		a.state.IP = ""
		a.state.Transport = ""
		a.state.Latency = 0
		a.state.Notice = ""
		a.state.Pushed = nil
		a.state.LeaseUntil = 0
	}
}

// EnsureWintun 在启动时释放 wintun.dll 并加入 DLL 搜索路径。
func EnsureWintun() error {
	path, err := client.EnsureWintunDLL()
	if err != nil {
		return err
	}
	log.Printf("[gui] wintun 就绪: %s", path)
	return nil
}

// IsElevated 返回当前进程是否以管理员身份运行。
func IsElevated() bool { return isElevated() }

// jsQuote 把文本编码为 JS 字符串字面量。
func jsQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

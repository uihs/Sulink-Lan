//go:build windows

package gui

import (
	"log"
	"net"
	"sync"

	npsclient "ehang.io/nps/client"

	"sulink-lan/internal/config"
)

// npcLogger 把 NPS NPC 的日志桥接到标准 log（GUI 日志文件）。
type npcLogger struct{}

func (npcLogger) Info(format string, v ...interface{})  { log.Printf("[npc] "+format, v...) }
func (npcLogger) Error(format string, v ...interface{}) { log.Printf("[npc] ERROR: "+format, v...) }
func (npcLogger) Warn(format string, v ...interface{})  { log.Printf("[npc] WARN: "+format, v...) }
func (npcLogger) Trace(format string, v ...interface{}) { /* 不打印 trace */ }

// npcManager 管理内嵌的 NPS NPC 客户端生命周期。
type npcManager struct {
	mu     sync.Mutex
	trp    *npsclient.TRPClient
	cancel chan struct{}
}

func newNpcManager() *npcManager {
	return &npcManager{}
}

// start 在后台启动 NPC 连接。
func (m *npcManager) start(serverAddr, vkey string) {
	m.stop()

	if vkey == "" {
		log.Printf("[npc] 无 device_key，跳过 NPC 连接")
		return
	}

	host, _, err := net.SplitHostPort(config.NormalizeServerAddr(serverAddr))
	if err != nil {
		log.Printf("[npc] 解析服务器地址失败: %v", err)
		return
	}
	bridgeAddr := net.JoinHostPort(host, "8024")

	log.Printf("[npc] 正在连接 NPS bridge %s", bridgeAddr)

	trp := npsclient.NewRPClient(bridgeAddr, vkey, "tcp", "", nil, 0)
	trp.SetLogger(npcLogger{})
	cancel := make(chan struct{})

	m.mu.Lock()
	m.trp = trp
	m.cancel = cancel
	m.mu.Unlock()

	go func() {
		trp.Start()
		log.Printf("[npc] NPC 连接已退出")
	}()

	go func() {
		<-cancel
		trp.Close()
	}()
}

func (m *npcManager) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		select {
		case <-m.cancel:
		default:
			close(m.cancel)
		}
		m.cancel = nil
	}
	if m.trp != nil {
		m.trp.Close()
		m.trp = nil
	}
}

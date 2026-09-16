package client

import (
	"log"

	"sulink-lan/internal/protocol"
)

// applyPushedConfig 应用服务端下发的配置。
//
// 语义是「整体替换」而不是「增量合并」：服务端每次下发的都是**当前完整**的
// 生效配置（见 server.Push），客户端照着它覆盖即可。若这里改成合并，
// 管理员在管理页把公告清空后，客户端会一直保留着旧公告——一个只能改不能删的配置项。
//
// 不认识的键不报错，照样存下来：管理页可能比客户端版本更新，
// 老客户端遇到新键时应当忽略而非中断。协议因此可以只增不改地演进。
func (c *Client) applyPushedConfig(cfg map[string]string) {
	c.pushMu.Lock()
	c.pushed = make(map[string]string, len(cfg))
	for k, v := range cfg {
		if v != "" {
			c.pushed[k] = v
		}
	}
	snapshot := make(map[string]string, len(c.pushed))
	for k, v := range c.pushed {
		snapshot[k] = v
	}
	c.pushMu.Unlock()

	// no_punch：立即生效。信令循环每次用之前都读一次原子量，
	// 所以下一台设备上线时就会按新策略走中转，不需要重连。
	// 已经建立的 P2P 直连不会被打断——强行拆掉既有连接会造成正在传输的业务中断，
	// 而管理员的意图通常是「之后别再用直连」。
	if v, ok := snapshot[protocol.CfgNoPunch]; ok {
		on := protocol.ParseBool(v)
		c.noPunch.Store(on)
		log.Printf("[client] 服务端下发：禁止 P2P 打洞 = %v（对后续新连接生效）", on)
	} else {
		// 该键被清除：回退到本机配置
		c.noPunch.Store(c.cfg.NoPunch)
	}
	if v, ok := snapshot[protocol.CfgNotice]; ok {
		log.Printf("[client] 服务端公告：%s", v)
	}
}

// PushedConfig 返回服务端下发并已生效的配置副本（无配置时返回空 map）。
func (c *Client) PushedConfig() map[string]string {
	c.pushMu.Lock()
	defer c.pushMu.Unlock()
	out := make(map[string]string, len(c.pushed))
	for k, v := range c.pushed {
		out[k] = v
	}
	return out
}

// Notice 返回服务端下发的公告文本；没有公告时返回空串。
func (c *Client) Notice() string {
	c.pushMu.Lock()
	defer c.pushMu.Unlock()
	return c.pushed[protocol.CfgNotice]
}

// LeaseUntil 返回虚拟 IP 租约到期时刻（Unix 秒），0 表示无租约信息。
func (c *Client) LeaseUntil() int64 {
	return c.leaseUntil.Load()
}

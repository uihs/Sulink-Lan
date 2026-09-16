package client

import (
	"context"
	"testing"
	"time"

	"sulink-lan/internal/protocol"
	"sulink-lan/internal/server"
)

// TestApplyPushedConfigNoPunchLive 下发的 no_punch 应立即改变客户端的打洞行为。
//
// 「立即」是这里的关键：信令循环每次用之前都读一次原子量，
// 所以不需要重连就能生效。若实现成「重连后生效」，用户点了下发却看不到任何变化，
// 会以为功能坏了。
func TestApplyPushedConfigNoPunchLive(t *testing.T) {
	c := NewClient(Config{Server: "127.0.0.1:1", Name: "x"})
	if c.noPunch.Load() {
		t.Fatal("初始不应禁止打洞")
	}

	c.applyPushedConfig(map[string]string{protocol.CfgNoPunch: "1"})
	if !c.noPunch.Load() {
		t.Fatal("下发 no_punch=1 后应立即禁止打洞")
	}

	// 宽松写法也应被接受（管理页是手输表单）
	c.applyPushedConfig(map[string]string{protocol.CfgNoPunch: "true"})
	if !c.noPunch.Load() {
		t.Fatal("no_punch=true 应被识别")
	}

	// 反向对照：清除该键后应回退到本机配置（本机未开启 → false）
	c.applyPushedConfig(map[string]string{})
	if c.noPunch.Load() {
		t.Fatal("清除 no_punch 后应回退到本机配置")
	}
}

// TestApplyPushedConfigReplacesInsteadOfMerges 下发是整体替换，不是增量合并。
//
// 若实现成合并，「管理员清空公告」这条路径就断了：客户端会一直挂着旧公告，
// 变成一个只能改、不能删的配置项。
func TestApplyPushedConfigReplacesInsteadOfMerges(t *testing.T) {
	c := NewClient(Config{Server: "127.0.0.1:1", Name: "x"})

	c.applyPushedConfig(map[string]string{protocol.CfgNotice: "旧公告", protocol.CfgNoPunch: "1"})
	if c.Notice() != "旧公告" {
		t.Fatalf("公告未生效: %q", c.Notice())
	}

	// 服务端下一次只带 no_punch（公告已被清除）
	c.applyPushedConfig(map[string]string{protocol.CfgNoPunch: "1"})
	if got := c.Notice(); got != "" {
		t.Fatalf("公告应被清除，实际仍为 %q", got)
	}
	if !c.noPunch.Load() {
		t.Fatal("清除公告不应影响 no_punch")
	}
}

// TestApplyPushedConfigIgnoresUnknownKeys 不认识的键只保存、不报错。
//
// 管理页可能比客户端新，老客户端遇到新键必须能继续工作，
// 否则「服务端升级」就会变成「所有老客户端连不上」。
func TestApplyPushedConfigIgnoresUnknownKeys(t *testing.T) {
	c := NewClient(Config{Server: "127.0.0.1:1", Name: "x"})
	c.applyPushedConfig(map[string]string{"future_option": "42", protocol.CfgNotice: "hi"})

	if c.Notice() != "hi" {
		t.Fatal("已知键应正常生效")
	}
	if got := c.PushedConfig()["future_option"]; got != "42" {
		t.Fatalf("未知键应原样保留以便展示，实际 %q", got)
	}
}

// TestConfigPushEndToEnd 端到端：管理页下发 → 服务端广播 → 真实客户端应用。
func TestConfigPushEndToEnd(t *testing.T) {
	srv, err := server.New(server.Config{TCPAddr: "127.0.0.1:0", UDPAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Run(ctx)
	t.Cleanup(cancel)

	deadline := time.Now().Add(3 * time.Second)
	for srv.Addr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("服务器未就绪")
		}
		time.Sleep(30 * time.Millisecond)
	}

	tun := newMockTun("push-tun")
	c := NewClient(Config{Server: srv.Addr(), Name: "push-client", HWID: "hwid-push"})
	c.newTun = func() (Tun, error) { return tun, nil }
	go c.Run()
	t.Cleanup(c.Close)
	waitVIP(t, c)
	waitReady(t, c)

	// 下发一条公告 + 禁止打洞
	if n := srv.Push(map[string]string{
		protocol.CfgNotice:  "本服务器今晚维护",
		protocol.CfgNoPunch: "1",
	}); n != 1 {
		t.Fatalf("应投递给 1 台在线设备，实际 %d", n)
	}

	// 客户端侧异步应用，轮询等待
	deadline = time.Now().Add(3 * time.Second)
	for {
		if c.Notice() == "本服务器今晚维护" && c.noPunch.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("客户端未应用下发配置: notice=%q noPunch=%v", c.Notice(), c.noPunch.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 再清空公告：客户端必须跟着清掉
	srv.Push(map[string]string{protocol.CfgNotice: ""})
	deadline = time.Now().Add(3 * time.Second)
	for {
		if c.Notice() == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("公告未被清除: %q", c.Notice())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 反向对照：no_punch 不受清除公告影响
	if !c.noPunch.Load() {
		t.Fatal("清除公告时不应连带清除 no_punch")
	}
}

// Package admin 提供 Sulink Lan 服务端的 Web 管理页。
//
// 设计取舍：
//
//   - **默认只监听回环地址**。管理页能踢人下线、能下发策略，
//     暴露到公网等于把服务器交给扫描器。要远程管理请显式指定监听地址，
//     并自行套一层反向代理 + HTTPS。
//   - **令牌走请求头**，不放在 URL 查询串里：查询串会进浏览器历史、
//     反向代理访问日志，等于把口令写在日志里。
//   - **页面本身不含机密**，因此 HTML 可以公开；真正需要鉴权的是 /api/*。
//     这样即使有人扫到这个端口，也拿不到任何信息（只是一个空壳页面）。
//   - **零第三方依赖**：与服务端其余部分一致，不引入前端框架/CDN，
//     离线环境与内网部署都能直接用。
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"sulink-lan/internal/server"
)

// maxBody 请求体上限。管理页只会发几十字节的 JSON，
// 给 64KB 足够宽松，同时挡住「往这里灌几个 G」这类低级骚扰。
const maxBody = 64 << 10

// Control 管理页需要的服务端能力。
//
// 定义成接口而不是直接依赖 *server.Server：测试里可以塞一个假实现，
// 不必为了测 HTTP 层去起一整套信令+中继服务。
//
// 为什么既有通用的 Push 又有 SetDeviceForward / SetDeviceIP：
// 前者面向「所有设备共用的全局配置」（公告、禁止打洞），
// 后者面向「按设备保存的东西」（IP 租约、穿透规则）。
// 二者作用域不同、落盘文件也不同，混成一个接口只会让调用方去猜
// 某个 key 到底该塞进哪个 map。
type Control interface {
	Snapshot() server.Snapshot
	Push(cfg map[string]string) int
	// SetDeviceForward 保存某设备的穿透规则；返回是否已即时推送给在线设备
	SetDeviceForward(hwid string, rules []string) (bool, error)
	// SetDeviceIP 改写某设备的虚拟 IP 租约
	SetDeviceIP(hwid, vip string) (bool, error)
	// RevokeDeviceCredential 清除设备凭证并封禁它
	RevokeDeviceCredential(hwid string) bool
	// UnblockDevice 解除设备封禁
	UnblockDevice(hwid string) bool
}

// Config 管理页配置。
type Config struct {
	Addr  string // 监听地址，如 127.0.0.1:8080
	Token string // 访问令牌（必填）
}

// Server Web 管理页服务。
type Server struct {
	cfg Config
	ctl Control
	srv *http.Server
}

// New 创建管理页服务。
func New(cfg Config, ctl Control) (*Server, error) {
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("管理页令牌不能为空")
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	s := &Server{cfg: cfg, ctl: ctl}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/state", s.auth(s.handleState))
	mux.HandleFunc("/api/push", s.auth(s.handlePush))
	// 每项下发功能各走一个独立端点：管理页上它们也是互相独立的卡片，
	// 「改公告」不会顺带把「禁止打洞」一起提交（那样任何一次误触都会
	// 覆盖掉另一项，而管理员根本看不出发生了什么）。
	mux.HandleFunc("/api/notice", s.auth(s.handleNotice))
	mux.HandleFunc("/api/nopunch", s.auth(s.handleNoPunch))
	mux.HandleFunc("/api/ip", s.auth(s.handleSetIP))
	mux.HandleFunc("/api/revoke-cred", s.auth(s.handleRevokeCred))
	mux.HandleFunc("/api/unblock", s.auth(s.handleUnblock))
	// NPS 公网访问管理（npc 客户端 + 隧道）
	mux.HandleFunc("/api/nps/clients", s.auth(s.handleNpsClients))
	mux.HandleFunc("/api/nps/clients/delete", s.auth(s.handleNpsClientDelete))
	mux.HandleFunc("/api/nps/tunnels", s.auth(s.handleNpsTunnels))
	mux.HandleFunc("/api/nps/tunnels/delete", s.auth(s.handleNpsTunnelDelete))
	// 客户端自助查询自己的隧道列表（用 device_key 认证，不需要 admin token）
	mux.HandleFunc("/api/sulink/my-tunnels", s.handleMyTunnels)
	s.srv = &http.Server{
		Addr:    cfg.Addr,
		Handler: s.securityHeaders(mux),
		// 超时全部显式设置：管理页是暴露在端口上的服务，
		// 没有超时的话一个挂起的连接就能长期占住 goroutine。
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

// Run 启动 HTTP 服务并阻塞至 ctx 取消。
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("管理页监听失败: %w", err)
	}

	// 监听在非回环地址时明确告警：这是把管理入口暴露给了整个网络，
	// 属于「有意为之但很容易疏忽」的配置，值得在日志里留一行。
	if host, _, err := net.SplitHostPort(ln.Addr().String()); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
			log.Printf("[admin] 注意：管理页监听在非回环地址 %s，任何能访问该端口的人都可尝试管理你的服务器。"+
				"请确保前面有反向代理 + HTTPS，并使用足够强的令牌", host)
		}
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
	}()

	if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// securityHeaders 给所有响应加上安全响应头。
//
// CSP 里没有内联脚本之外的白名单：页面是单文件、零外链，
// 因此可以直接禁掉一切外部资源，把 XSS 的可利用面压到最小。
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// auth 校验令牌。令牌从请求头读取，常量时间比较避免逐字节试探。
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Admin-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
			// 日志只记录长度，绝不记录令牌本身——但长度这一项就足以区分
			// 「抄错了」（长度不对）和「请求压根没带上令牌」（长度为 0），
			// 排查时省去来回猜。
			log.Printf("[admin] 拒绝访问 %s：令牌不匹配（收到 %d 字符，期望 %d 字符）",
				r.RemoteAddr, len(got), len(s.cfg.Token))
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":    false,
				"error": "令牌不正确",
			})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, pageHTML)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": s.ctl.Snapshot()})
}

// pushReq 下发配置请求体。
type pushReq struct {
	Config map[string]string `json:"config"`
}

// handlePush 通用下发端点（一次提交多个配置项）。
//
// 管理页**不使用**它——页面上的公告、禁止打洞是两张独立卡片，
// 各走 /api/notice 与 /api/nopunch，避免「改一项顺带覆盖另一项」。
// 保留这个端点是给脚本用的：批量下发多个键一次往返，比逐个调用省事。
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req pushReq
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(req.Config) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "没有要下发的配置项"})
		return
	}
	n := s.ctl.Push(req.Config)
	log.Printf("[admin] 下发配置 %v，投递给 %d 台在线设备", req.Config, n)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "delivered": n})
}

// noticeReq 公告请求体。Text 为空表示删除公告。
type noticeReq struct {
	Text string `json:"text"`
}

// handleNotice 发布或删除公告。
//
// 删除就是「下发一个空值」：服务端 Push 把空串解释为清除该项，
// 因此不需要一个单独的 DELETE 端点，也就不会出现
// 「发布走一个接口、删除走另一个接口，两边校验规则不一致」的分裂。
func (s *Server) handleNotice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req noticeReq
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	text := strings.TrimSpace(req.Text)
	n := s.ctl.Push(map[string]string{"notice": text})
	if text == "" {
		log.Printf("[admin] 删除公告，投递给 %d 台在线设备", n)
	} else {
		log.Printf("[admin] 更新公告（%d 字符），投递给 %d 台在线设备", len([]rune(text)), n)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "delivered": n, "deleted": text == ""})
}

// nopunchReq 禁止打洞开关请求体。
type nopunchReq struct {
	On bool `json:"on"`
}

// handleNoPunch 单独设置「禁止 P2P 打洞」。
//
// 关掉时下发空串而不是 "0"：服务端约定的「空值即删除」让配置里
// 只存在「有这一项」和「没这一项」两种状态，不必再区分
// "0" / "false" / "off" 这些客户端可能各自解释不同的写法。
func (s *Server) handleNoPunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req nopunchReq
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	val := ""
	if req.On {
		val = "1"
	}
	n := s.ctl.Push(map[string]string{"no_punch": val})
	log.Printf("[admin] 禁止打洞 = %v，投递给 %d 台在线设备", req.On, n)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "delivered": n})
}

// setIPReq 改地址请求体。
type setIPReq struct {
	HWID string `json:"hwid"`
	VIP  string `json:"vip"`
}

// handleSetIP 改写某设备的虚拟 IP 租约。
//
// 返回 reconnect 让管理页能给出准确提示：在线设备是被主动断开后
// 自动重连生效的（TUN 地址无法热改），离线设备则下次上线生效。
func (s *Server) handleSetIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req setIPReq
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	reconnect, err := s.ctl.SetDeviceIP(strings.TrimSpace(req.HWID), strings.TrimSpace(req.VIP))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	log.Printf("[admin] 设备 %s 的地址改为 %s（已断开等待重连: %v）", req.HWID, req.VIP, reconnect)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reconnect": reconnect})
}

// revokeCredReq 清除设备凭证请求体。
type revokeCredReq struct {
	HWID string `json:"hwid"`
}

// handleRevokeCred 清除设备的注册凭证（设备丢失/重装后使用）。
// 清除后设备下次连接将认证失败，随即按自动注册流程重新注册并拿回原凭证。
func (s *Server) handleRevokeCred(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req revokeCredReq
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if strings.TrimSpace(req.HWID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "缺少设备标识"})
		return
	}
	if !s.ctl.RevokeDeviceCredential(strings.TrimSpace(req.HWID)) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "该设备未注册或凭证不存在"})
		return
	}
	log.Printf("[admin] 已清除设备的注册凭证并封禁 %s", strings.TrimSpace(req.HWID))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// unblockReq 解除封禁请求体。
type unblockReq struct {
	HWID string `json:"hwid"`
}

// handleUnblock 解除设备封禁（被「清除凭证/踢下线」封掉后，由管理员放行）。
func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req unblockReq
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if strings.TrimSpace(req.HWID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "缺少设备标识"})
		return
	}
	if !s.ctl.UnblockDevice(strings.TrimSpace(req.HWID)) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "该设备未被封禁"})
		return
	}
	log.Printf("[admin] 已解除设备封禁 %s", strings.TrimSpace(req.HWID))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// decodeBody 读取并解析 JSON 请求体（带大小上限）。
func decodeBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("请求内容不是合法的 JSON: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

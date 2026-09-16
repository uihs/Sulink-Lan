package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sulink-lan/internal/server"
)

// fakeControl 记录被调用情况的假实现。
//
// 用假实现而不是真起一套信令服务：这一层要验证的是「路由、鉴权、参数校验」，
// 与设备表如何维护无关。用真的反而让失败原因变得含糊（到底是 HTTP 层错了还是服务端错了）。
type fakeControl struct {
	snap      server.Snapshot
	pushed    map[string]string
	pushCalls int

	// 设备级操作（穿透规则 / 改地址）的记录
	forwardHWID  string
	forwardRules []string
	forwardDeliv bool
	forwardErr   error

	ipHWID      string
	ipVIP       string
	ipReconnect bool
	ipErr       error
}

func (f *fakeControl) Snapshot() server.Snapshot { return f.snap }
func (f *fakeControl) RevokeDeviceCredential(hwid string) bool { return true }
func (f *fakeControl) UnblockDevice(hwid string) bool            { return true }
func (f *fakeControl) Push(cfg map[string]string) int {
	f.pushCalls++
	f.pushed = cfg
	return 3
}
func (f *fakeControl) SetDeviceForward(hwid string, rules []string) (bool, error) {
	if f.forwardErr != nil {
		return false, f.forwardErr
	}
	f.forwardHWID = hwid
	f.forwardRules = rules
	return f.forwardDeliv, nil
}

func (f *fakeControl) SetDeviceIP(hwid, vip string) (bool, error) {
	if f.ipErr != nil {
		return false, f.ipErr
	}
	f.ipHWID = hwid
	f.ipVIP = vip
	return f.ipReconnect, nil
}

const testToken = "unit-test-token"

func newTestServer(t *testing.T, ctl Control) http.Handler {
	t.Helper()
	s, err := New(Config{Addr: "127.0.0.1:0", Token: testToken}, ctl)
	if err != nil {
		t.Fatal(err)
	}
	return s.srv.Handler
}

func do(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		r.Header.Set("X-Admin-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestNewRejectsEmptyToken 空令牌必须拒绝创建。
//
// 这是「默认安全」的底线：若允许空令牌，管理页就等于完全无鉴权，
// 而它恰好拥有踢人下线和下发策略的能力。
func TestNewRejectsEmptyToken(t *testing.T) {
	if _, err := New(Config{Addr: "127.0.0.1:0", Token: ""}, &fakeControl{}); err == nil {
		t.Fatal("空令牌应被拒绝")
	}
	if _, err := New(Config{Addr: "127.0.0.1:0", Token: "   "}, &fakeControl{}); err == nil {
		t.Fatal("纯空白令牌应被拒绝")
	}
}

// TestIndexNeedsNoToken 页面本身不含机密，无需鉴权即可打开（否则用户没法输入令牌）。
func TestIndexNeedsNoToken(t *testing.T) {
	h := newTestServer(t, &fakeControl{})
	w := do(h, http.MethodGet, "/", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("首页应可匿名访问，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Sulink Lan") {
		t.Fatal("首页内容异常")
	}
	// 首页绝不能把令牌泄露出去
	if strings.Contains(w.Body.String(), testToken) {
		t.Fatal("首页响应中出现了管理令牌")
	}
}

// TestAPIRoutesRequireToken 所有 /api/* 都必须鉴权。
func TestAPIRoutesRequireToken(t *testing.T) {
	h := newTestServer(t, &fakeControl{})
	cases := []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/state", ""},
		{http.MethodPost, "/api/push", `{"config":{"notice":"x"}}`},
		{http.MethodPost, "/api/notice", `{"text":"x"}`},
		{http.MethodPost, "/api/nopunch", `{"on":true}`},
		{http.MethodPost, "/api/ip", `{"hwid":"ab","vip":"10.0.0.9"}`},
		{http.MethodPost, "/api/revoke-cred", `{"hwid":"ab"}`},
		{http.MethodPost, "/api/unblock", `{"hwid":"ab"}`},
		{http.MethodGet, "/api/nps/clients", ""},
		{http.MethodPost, "/api/nps/clients/delete", `{"id":1}`},
		{http.MethodGet, "/api/nps/tunnels", ""},
		{http.MethodPost, "/api/nps/tunnels/delete", `{"id":1}`},
	}
	for _, c := range cases {
		// 无令牌
		if w := do(h, c.method, c.path, "", c.body); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 无令牌应 401，实际 %d", c.method, c.path, w.Code)
		}
		// 错误令牌
		if w := do(h, c.method, c.path, "wrong", c.body); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 错误令牌应 401，实际 %d", c.method, c.path, w.Code)
		}
	}
}

// TestStateReturnsSnapshot 带正确令牌应返回完整状态。
func TestStateReturnsSnapshot(t *testing.T) {
	ctl := &fakeControl{snap: server.Snapshot{
		ServerVIP: "10.0.0.1",
		VNet:      "10.0.0.0/8",
		Devices:   []server.DeviceInfo{{Name: "pc-a", VIP: "10.0.0.2"}},
		Leases: []server.LeaseInfo{
			{HWID: "aaaa1111", Name: "pc-a", VIP: "10.0.0.2", Online: true, RemainSecs: 100, Forward: []string{"8080=10.0.0.2:80"}},
		},
		LeaseDays: 31,
		Stats:     server.Stats{PktsRelayed: 7},
	}}
	h := newTestServer(t, ctl)

	w := do(h, http.MethodGet, "/api/state", testToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("状态接口应 200，实际 %d", w.Code)
	}
	var resp struct {
		OK    bool            `json:"ok"`
		State server.Snapshot `json:"state"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.State.ServerVIP != "10.0.0.1" || len(resp.State.Devices) != 1 {
		t.Fatalf("状态内容不符: %+v", resp)
	}
	if resp.State.Stats.PktsRelayed != 7 {
		t.Fatalf("统计未透传: %+v", resp.State.Stats)
	}
	// 租约表是管理页改地址与配穿透规则的唯一数据来源，必须完整透传
	if len(resp.State.Leases) != 1 {
		t.Fatalf("租约未透传: %+v", resp.State.Leases)
	}
	li := resp.State.Leases[0]
	if li.HWID != "aaaa1111" || !li.Online || len(li.Forward) != 1 || resp.State.LeaseDays != 31 {
		t.Fatalf("租约字段不符: %+v (leaseDays=%d)", li, resp.State.LeaseDays)
	}
}

// TestPushValidatesAndForwards 下发接口的参数校验与转发。
func TestPushValidatesAndForwards(t *testing.T) {
	ctl := &fakeControl{}
	h := newTestServer(t, ctl)

	// 空配置：拒绝，且不得调用底层
	if w := do(h, http.MethodPost, "/api/push", testToken, `{"config":{}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("空配置应 400，实际 %d", w.Code)
	}
	if ctl.pushCalls != 0 {
		t.Fatal("空配置不应触达底层下发")
	}

	// 非法 JSON：拒绝
	if w := do(h, http.MethodPost, "/api/push", testToken, `{not json`); w.Code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应 400，实际 %d", w.Code)
	}

	// 正常下发
	w := do(h, http.MethodPost, "/api/push", testToken, `{"config":{"notice":"维护中"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("下发应 200，实际 %d (%s)", w.Code, w.Body.String())
	}
	if ctl.pushCalls != 1 || ctl.pushed["notice"] != "维护中" {
		t.Fatalf("下发未正确转发: %+v", ctl.pushed)
	}
	var resp struct {
		Delivered int `json:"delivered"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Delivered != 3 {
		t.Fatalf("投递数未回传: %d", resp.Delivered)
	}
}

// TestNoticePublishAndDelete 公告的两条路径：发布、单独删除。
//
// 删除走的是「下发空值」，服务端把空串解释为清除该项。
// 这里断言的是「空串确实被原样传下去」——若中间层自作聪明地
// 把空值当成「没填」过滤掉，删除按钮就会变成一个假控件。
func TestNoticePublishAndDelete(t *testing.T) {
	ctl := &fakeControl{}
	h := newTestServer(t, ctl)

	if w := do(h, http.MethodPost, "/api/notice", testToken, `{"text":"  今晚 22:00 维护  "}`); w.Code != http.StatusOK {
		t.Fatalf("发布公告应 200，实际 %d", w.Code)
	}
	if ctl.pushed["notice"] != "今晚 22:00 维护" {
		t.Fatalf("公告未按预期下发: %q", ctl.pushed["notice"])
	}

	w := do(h, http.MethodPost, "/api/notice", testToken, `{"text":""}`)
	if w.Code != http.StatusOK {
		t.Fatalf("删除公告应 200，实际 %d", w.Code)
	}
	if v, ok := ctl.pushed["notice"]; !ok || v != "" {
		t.Fatalf("删除公告必须下发空值，实际 %q（键存在=%v）", v, ok)
	}
	var resp struct {
		Deleted bool `json:"deleted"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Deleted {
		t.Fatal("删除操作未在回执中标记")
	}
}

// TestNoPunchUsesEmptyValueToClear 关掉开关时下发空串，而不是 "0"。
//
// 服务端约定「空值即删除」，因此配置里只存在「有这一项」和「没这一项」
// 两种状态；若这里改成下发 "0"，客户端就得同时理解 "0"/"false"/"off"，
// 多一处能解释错的地方。
func TestNoPunchUsesEmptyValueToClear(t *testing.T) {
	ctl := &fakeControl{}
	h := newTestServer(t, ctl)

	if w := do(h, http.MethodPost, "/api/nopunch", testToken, `{"on":true}`); w.Code != http.StatusOK {
		t.Fatalf("开启应 200，实际 %d", w.Code)
	}
	if ctl.pushed["no_punch"] != "1" {
		t.Fatalf("开启应下发 \"1\"，实际 %q", ctl.pushed["no_punch"])
	}

	if w := do(h, http.MethodPost, "/api/nopunch", testToken, `{"on":false}`); w.Code != http.StatusOK {
		t.Fatalf("关闭应 200，实际 %d", w.Code)
	}
	if v := ctl.pushed["no_punch"]; v != "" {
		t.Fatalf("关闭应下发空串（表示清除该项），实际 %q", v)
	}
}

// 说明：原先这里还有一组 /api/forward 的用例。穿透规则与公网端口映射合并之后，
// 管理页不再提供按设备下发穿透规则的入口（服务端成了唯一入口），该端点随之删除，
// 相应用例一并移除——保留它们只会让「测试红了」变成一种常态，掩盖真正的新问题。

// TestSetIPReportsReconnect 改地址必须如实回报「是否断开了在线设备」。
//
// 在线设备是主动断开后自动重连生效的，离线设备则要等下次上线，
// 两种情况管理页给出的提示不同，所以这个布尔值不能糊弄。
func TestSetIPReportsReconnect(t *testing.T) {
	ctl := &fakeControl{ipReconnect: true}
	h := newTestServer(t, ctl)

	w := do(h, http.MethodPost, "/api/ip", testToken, `{"hwid":"abcd","vip":" 10.0.0.9 "}`)
	if w.Code != http.StatusOK {
		t.Fatalf("改地址应 200，实际 %d (%s)", w.Code, w.Body.String())
	}
	if ctl.ipHWID != "abcd" || ctl.ipVIP != "10.0.0.9" {
		t.Fatalf("参数未按预期转发: %q %q", ctl.ipHWID, ctl.ipVIP)
	}
	var resp struct {
		Reconnect bool `json:"reconnect"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Reconnect {
		t.Fatal("重连标志未回传")
	}

	// 地址非法（由服务端判定）时应回 400，而不是假装成功
	ctl.ipErr = errStub("地址 10.1.0.1 不可分配")
	if w := do(h, http.MethodPost, "/api/ip", testToken, `{"hwid":"abcd","vip":"10.1.0.1"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("非法地址应 400，实际 %d", w.Code)
	}
}

// TestKickForwardsError 踢下线失败时把原因回给管理页。
// TestMethodNotAllowed 写接口不接受 GET，读接口不接受 POST。
func TestMethodNotAllowed(t *testing.T) {
	h := newTestServer(t, &fakeControl{})
	for _, path := range []string{
		"/api/push", "/api/notice", "/api/nopunch", "/api/ip",
		"/api/revoke-cred", "/api/unblock",
		"/api/nps/clients/delete", "/api/nps/tunnels/delete",
	} {
		if w := do(h, http.MethodGet, path, testToken, ""); w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s 应 405，实际 %d", path, w.Code)
		}
	}
	if w := do(h, http.MethodPost, "/api/state", testToken, `{}`); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/state 应 405，实际 %d", w.Code)
	}
}

// TestSecurityHeaders 安全响应头必须存在（防嗅探 / 防嵌套 / 不缓存）。
func TestSecurityHeaders(t *testing.T) {
	h := newTestServer(t, &fakeControl{})
	w := do(h, http.MethodGet, "/", "", "")
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Cache-Control":          "no-store",
	} {
		if got := w.Header().Get(k); got != want {
			t.Fatalf("响应头 %s = %q，期望 %q", k, got, want)
		}
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("CSP 未收紧: %q", csp)
	}
}

// TestUnknownPath404 未注册路径返回 404 而不是首页内容。
func TestUnknownPath404(t *testing.T) {
	h := newTestServer(t, &fakeControl{})
	if w := do(h, http.MethodGet, "/../secret", "", ""); w.Code == http.StatusOK {
		t.Fatal("未知路径不应返回 200")
	}
}

type errStub string

func (e errStub) Error() string { return string(e) }

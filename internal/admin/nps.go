package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"ehang.io/nps/lib/file"
	"ehang.io/nps/server"
)

// ===== NPS 管理 API =====
//
// 直接调用 NPS 自身的数据层（file.GetDb()）和运行时（server.*），
// 不经过 NPS 的 beego Web 面板。所有字段都做最小化白名单，
// 只暴露常用的 TCP/UDP/SOCKS5 隧道与 npc 客户端管理。

func (s *Server) handleNpsClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db := file.GetDb()
	if r.Method == http.MethodGet {
		// 用 server.GetClientList 而非 db.GetClientList：前者会先 dealClientData()
		// 把 Bridge.Client 里的在线状态同步到 IsConnect 字段，否则永远显示离线。
		list, total := server.GetClientList(0, 9999, "", "id", "asc", 0)
		out := make([]map[string]any, 0, len(list))
		for _, c := range list {
			out = append(out, map[string]any{
				"id":         c.Id,
				"vkey":       c.VerifyKey,
				"remark":     c.Remark,
				"online":     c.IsConnect,
				"addr":       c.Addr,
				"status":     c.Status,
				"createTime": c.CreateTime,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "total": total, "items": out})
		return
	}

	// POST: 新增 npc 客户端（vkey）
	var body struct {
		Vkey   string `json:"vkey"`
		Remark string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数解析失败"})
		return
	}
	if body.Vkey == "" {
		// 自动生成一个 vkey
		body.Vkey = fmt.Sprintf("client-%d", db.JsonDb.GetClientId())
	}
	c := file.NewClient(body.Vkey, false, false)
	c.Remark = body.Remark
	if err := db.NewClient(c); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": c.Id, "vkey": c.VerifyKey})
}

func (s *Server) handleNpsClientDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "id 无效"})
		return
	}
	if err := file.GetDb().DelClient(body.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleNpsTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db := file.GetDb()
	if r.Method == http.MethodGet {
		// server.GetTunnel 在 clientId=0 时会按 Client.Id 过滤（0 != 真实 clientId），
		// 导致查不到任何隧道。直接遍历所有任务，手动填充运行状态。
		all := make([]*file.Tunnel, 0)
		db.JsonDb.Tasks.Range(func(key, value interface{}) bool {
			t := value.(*file.Tunnel)
			if clientID, _ := strconv.Atoi(r.URL.Query().Get("client_id")); clientID != 0 && t.Client != nil && t.Client.Id != clientID {
				return true
			}
			if tp := r.URL.Query().Get("type"); tp != "" && t.Mode != tp {
				return true
			}
			if _, ok := server.RunList.Load(t.Id); ok {
				t.RunStatus = true
			} else {
				t.RunStatus = false
			}
			if t.Client != nil {
				if _, ok := server.Bridge.Client.Load(t.Client.Id); ok {
					t.Client.IsConnect = true
				} else {
					t.Client.IsConnect = false
				}
			}
			all = append(all, t)
			return true
		})
		list := all
		total := len(list)
		out := make([]map[string]any, 0, len(list))
		for _, t := range list {
			target := ""
			if t.Target != nil {
				target = t.Target.TargetStr
			}
			clientID := 0
			vkey := ""
			if t.Client != nil {
				clientID = t.Client.Id
				vkey = t.Client.VerifyKey
			}
			out = append(out, map[string]any{
				"id":       t.Id,
				"port":     t.Port,
				"mode":     t.Mode,
				"target":   target,
				"remark":   t.Remark,
				"running":  t.RunStatus,
				"clientId": clientID,
				"vkey":     vkey,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "total": total, "items": out})
		return
	}

	// POST: 新增隧道
	var body struct {
		ClientID int    `json:"client_id"`
		Port     int    `json:"port"`
		Mode     string `json:"mode"`
		Target   string `json:"target"`
		Remark   string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数解析失败"})
		return
	}
	if body.Mode == "" {
		body.Mode = "tcp"
	}
	if body.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "target 必填（host:port，npc 本机或局域网地址）"})
		return
	}
	cli, err := db.GetClient(body.ClientID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "client_id 无效: " + err.Error()})
		return
	}

	// "all" = 同时创建 TCP + UDP 两条隧道（同端口同目标）
	modes := []string{body.Mode}
	if body.Mode == "all" {
		modes = []string{"tcp", "udp"}
	}

	var lastTunnel *file.Tunnel
	for _, mode := range modes {
		t := &file.Tunnel{
			Id:       int(db.JsonDb.GetTaskId()),
			Port:     body.Port,
			Mode:     mode,
			Target:   &file.Target{TargetStr: body.Target},
			Client:   cli,
			Status:   true,
			Remark:   body.Remark,
			Flow:     &file.Flow{},
		}
		if err := db.NewTask(t); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := server.AddTask(t); err != nil {
			_ = db.DelTask(t.Id)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		lastTunnel = t
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": lastTunnel.Id, "port": lastTunnel.Port})
}

func (s *Server) handleNpsTunnelDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "id 无效"})
		return
	}
	if err := server.DelTask(body.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMyTunnels 返回指定 device_key 对应的隧道列表。
// 客户端不需要 admin token，用自己的 device_key 认证即可。
func (s *Server) handleMyTunnels(w http.ResponseWriter, r *http.Request) {
	vkey := r.URL.Query().Get("device_key")
	if vkey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "device_key 必填"})
		return
	}
	db := file.GetDb()
	// 通过 vkey 找到 NPS client ID
	clientID := 0
	db.JsonDb.Clients.Range(func(key, value interface{}) bool {
		c := value.(*file.Client)
		if c.VerifyKey == vkey {
			clientID = c.Id
			return false
		}
		return true
	})
	if clientID == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "items": []any{}})
		return
	}
	// 收集该 client 的所有隧道
	items := make([]map[string]any, 0)
	db.JsonDb.Tasks.Range(func(key, value interface{}) bool {
		t := value.(*file.Tunnel)
		if t.Client == nil || t.Client.Id != clientID {
			return true
		}
		target := ""
		if t.Target != nil {
			target = t.Target.TargetStr
		}
		running := false
		if _, ok := server.RunList.Load(t.Id); ok {
			running = true
		}
		items = append(items, map[string]any{
			"id":      t.Id,
			"port":    t.Port,
			"mode":    t.Mode,
			"target":  target,
			"remark":  t.Remark,
			"running": running,
		})
		return true
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "items": items})
}

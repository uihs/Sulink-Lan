package gui

import (
	"sulink-lan/internal/config"
)

// State 暴露给前端的运行状态快照。
type State struct {
	Status    string            `json:"status"`
	Message   string            `json:"message"`
	IP        string            `json:"ip"`
	Transport string            `json:"transport"`
	Latency   int               `json:"latency"`
	Logs      []string          `json:"logs"`
	Tunnels   []TunnelView      `json:"tunnels"`
	Config    config.Config     `json:"config"`
	Version   string            `json:"version"`
	Protocol  string            `json:"protocol"`
	Elevated  bool              `json:"elevated"`
	Busy      bool              `json:"busy"`
	Notice    string            `json:"notice"`
	Pushed    map[string]string `json:"pushed"`
	LeaseUntil int64            `json:"leaseUntil"`
}

// TunnelView NPS 隧道的前端展示结构。
type TunnelView struct {
	ID      int    `json:"id"`
	Port    int    `json:"port"`
	Mode    string `json:"mode"`
	Target  string `json:"target"`
	Remark  string `json:"remark"`
	Running bool   `json:"running"`
}

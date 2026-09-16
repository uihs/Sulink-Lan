package server

import (
	"log"
	"sort"
	"strings"
)

// 本文件负责「全局配置」的持久化：公告、禁止打洞等对所有设备一视同仁的策略。
//
// 与设备表（devices.go）分开存放：那份是「每台设备各自的地址与穿透规则」，
// 由程序高频改写；这份是「管理员对所有人下的通知与策略」，低频修改。
// 分成两个文件后，手工编辑其中一个不会连带影响另一个。
//
// 穿透规则**不在这里**：它是按设备下发的，存在设备表里。
// 早期版本曾把它塞进同一个 map，结果是服务端得回答「某台设备的规则和
// 全局规则谁优先」——一个本不该存在的问题。

// settingsFile 全局配置的落盘结构。
type settingsFile struct {
	Version int               `json:"version"`
	Config  map[string]string `json:"config"`
}

// loadSettings 读取全局配置文件。
//
// 文件不存在（首次运行）或内容损坏时返回空配置并继续启动：
// 全局配置是「锦上添花」的运行时策略，它读不出来不该让服务端起不来。
// 损坏的文件已被 readJSON 改名保留，不会丢现场。
func loadSettings(path string) map[string]string {
	out := make(map[string]string)
	if path == "" {
		return out
	}
	var f settingsFile
	loaded, err := readJSON(path, &f)
	if err != nil {
		log.Printf("[server] 全局配置读取失败，将以空配置启动: %v", err)
		return out
	}
	if !loaded {
		return out
	}
	for k, v := range f.Config {
		k = strings.TrimSpace(k)
		// 空值等同于「没有这一项」：管理页清空某个字段就是删除该项，
		// 若把空值也加载进来，客户端会收到一个「值为空」的配置项，
		// 与「从未下发过」在语义上无法区分。
		if k == "" || strings.TrimSpace(v) == "" {
			continue
		}
		out[k] = v
	}
	if len(out) > 0 {
		log.Printf("[server] 已加载全局配置 %s（生效项：%s）", path, strings.Join(sortedKeys(out), "、"))
	}
	return out
}

// saveSettings 写入全局配置文件。
func saveSettings(path string, cfg map[string]string) error {
	if path == "" {
		return nil
	}
	return writeJSON(path, settingsFile{Version: 1, Config: cfg})
}

// sortedKeys 返回排序后的键名，用于日志与提示里的稳定输出。
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

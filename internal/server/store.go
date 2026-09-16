package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// 本文件提供服务端两份持久化状态（设备表、全局配置）共用的文件读写。
//
// 为什么要落盘而不是只留内存：
//   - IP 租约承诺「同一台设备 31 天内拿回同一个地址」。若只存内存，
//     服务端一重启承诺就断了——而重启恰恰是最常发生的事（升级、迁移、崩溃恢复）。
//   - 公告承诺「新上线的设备也能看到」。只存内存时，管理员发完公告、
//     服务端重启一次，公告就凭空消失，且没有任何提示。
//
// 两份状态分成两个文件而不是塞进一个：设备表由程序高频改写、
// 全局配置由管理员低频修改，分开后手工编辑配置文件不会连带影响租约。

// readJSON 读取并解析 JSON 文件。
//
// 返回值 loaded 区分「文件不存在」（首次运行，正常）与「读取失败」。
// 内容损坏时把原文件改名为 <path>.bad 再返回错误：保留现场，
// 而不是让随后的一次保存把它覆盖掉——出问题时还能看到原来写了什么。
func readJSON(path string, dst any) (loaded bool, err error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		if bad := quarantine(path); bad != "" {
			log.Printf("[server] %s 内容损坏（%v），已备份为 %s，将以空状态继续运行", path, err, bad)
		}
		return false, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	return true, nil
}

// writeJSON 原子写入 JSON：先写临时文件再改名，权限 0600。
//
// 直接覆盖原文件时若中途失败（断电、磁盘满），会留下半截 JSON，
// 下次启动直接读不出来。改名在同一个文件系统内是原子操作，
// 因此要么是旧内容、要么是新内容，不会出现「半个文件」。
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// quarantine 把损坏的文件改名保留，返回新路径；失败时返回空串。
//
// 名字里带时间戳而不是简单的 .bad：损坏可能反复发生（比如磁盘有问题），
// 固定名字会让后一次覆盖前一次，最后只剩下最近一次的现场。
func quarantine(path string) string {
	bad := fmt.Sprintf("%s.bad-%s", path, time.Now().Format("20060102-150405"))
	if err := os.Rename(path, bad); err != nil {
		return ""
	}
	return bad
}

// absPath 返回绝对路径，便于启动日志里直接给出可复制的完整路径。
// 失败时原样返回：这只是为了让日志好看，不该因此影响启动。
func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

// filePathOrDisabled 与 absPath 相同，但把「空路径」明确说成未启用。
//
// 直接对空串调 absPath 会得到当前工作目录——一个看起来正常、
// 实际什么都没存的路径。这种日志比没有日志更误导人。
func filePathOrDisabled(p string) string {
	if p == "" {
		return "（未启用持久化，仅保存在内存中）"
	}
	return absPath(p)
}

//go:build windows

// wintun.dll 的自动释放。
//
// 背景：wireguard/tun 通过 syscall 按标准 DLL 搜索顺序加载 "wintun.dll"。
// 本程序把官方 wintun.dll 内嵌进二进制（go:embed），首次运行时释放到
// %APPDATA%\SulinkLan，并把该目录加入 DLL 搜索路径，用户无需手动下载。
//
// 释放策略：
//   - 目标路径：%APPDATA%\SulinkLan\wintun.dll（Roaming，不写 exe 目录）
//   - 若目标已存在且 sha256 一致 → 跳过（避免每次启动都写盘）
//   - 释放后用 SetDllDirectory/AddDllDirectory 加入搜索路径
package client

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// 各架构的 wintun.dll 由 wintun_embed_<arch>.go 分别内嵌（见同目录下的
// wintun_embed_amd64.go / _arm64.go / _386.go）。
//
// 为什么按架构拆分而不是一次 embed 三个：一个二进制只会用到与自己架构
// 匹配的那一份（wintunDLLBytes 按 runtime.GOARCH 取），另外两份纯属白带。
// 实测 amd64 构建下多带 386 + arm64 两份合计 755KB，占客户端体积 7%。
// 拆分后每个架构的产物只含自己那一份。

// wintunVersion 用于版本比对：dll 内容变化时强制覆盖旧文件。
const wintunVersion = "0.14.1"

// wintunDLLName 目标文件名，必须是 "wintun.dll" 才能被 searchpath 找到。
const wintunDLLName = "wintun.dll"

// EnsureWintunDLL 确保 wintun.dll 在可被加载的位置，返回其完整路径。
//
// 目标目录固定为 %APPDATA%\SulinkLan（Roaming）：
// 不往 exe 目录写文件，绿色版/解压即用场景也不会留下额外的 dll；
// 再把该目录加入 DLL 搜索路径，供 wireguard/tun 加载。
func EnsureWintunDLL() (string, error) {
	data, err := wintunDLLBytes()
	if err != nil {
		return "", err
	}

	dir, err := sulinkAppDataDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建 %s 失败: %w", dir, err)
	}
	target := filepath.Join(dir, wintunDLLName)
	if err := writeIfChanged(target, data); err != nil {
		return "", fmt.Errorf("释放 wintun.dll 失败: %w", err)
	}
	// 先按绝对路径把 dll 加载进当前进程。
	//
	// 为什么不能只靠 SetDllDirectory：wireguard/tun 用 syscall.NewLazyDLL("wintun.dll")
	// 加载，其底层 LoadLibrary 的搜索方式未必尊重 SetDllDirectory（实测仍报
	// "module not found"）。按绝对路径先 LoadLibrary 后，Windows 会把它记为
	// 已加载模块，后续任何地方再按基名 "wintun.dll" 加载都会直接命中，
	// 与搜索目录无关——这是最稳的兜底。句柄随进程存活，不释放。
	if err := loadLibraryByPath(target); err != nil {
		return "", fmt.Errorf("加载 %s 失败: %w", target, err)
	}
	// 同时把该目录加入 DLL 搜索路径（双保险）。
	_ = addDLLSearchDir(dir)
	return target, nil
}

// loadLibraryByPath 按绝对路径加载 DLL（句柄保持到进程结束）。
func loadLibraryByPath(absPath string) error {
	h, err := syscall.LoadLibrary(absPath)
	if err != nil {
		return err
	}
	runtime.KeepAlive(h)
	return nil
}

// sulinkAppDataDir 返回 %APPDATA%\SulinkLan（Roaming）。
// 取不到 UserConfigDir 时回退到 %APPDATA% 环境变量，再不行用 LOCALAPPDATA。
func sulinkAppDataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = os.Getenv("APPDATA")
	}
	if base == "" {
		base = os.Getenv("LOCALAPPDATA")
	}
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "SulinkLan"), nil
}

// wintunDLLBytes 取出当前架构对应的 dll 内容（由 wintun_embed_<arch>.go 提供）。
func wintunDLLBytes() ([]byte, error) {
	if len(wintunDLL) == 0 {
		return nil, fmt.Errorf("不支持的 CPU 架构: %s（wintun 仅支持 amd64/arm64/386）", runtime.GOARCH)
	}
	return wintunDLL, nil
}

// writeIfChanged 内容不同（或文件缺失）时写入，避免每次启动重复写盘。
func writeIfChanged(path string, data []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if sha256.Sum256(existing) == sha256.Sum256(data) {
			return nil // 已是同一版本
		}
	}
	// 先写临时文件再改名，避免写入中途失败留下损坏的 dll
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

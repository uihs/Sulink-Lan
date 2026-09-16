//go:build windows

package client

import (
	"fmt"
	"syscall"
	"unsafe"
)

// SetDllDirectoryW 追加 DLL 搜索目录。
// 说明：Windows 的 SetDllDirectory 会替换默认搜索目录，这里将其设为
// "默认目录 + 我们的目录" 的组合语义——实际上我们只需要加载 wintun.dll，
// 因此直接指向释放目录即可；系统 dll（kernel32 等）由 KnownDLLs 机制保证。
var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	procSetDllDir = kernel32.NewProc("SetDllDirectoryW")
	procAddDllDir = kernel32.NewProc("AddDllDirectory")
)

// addDLLSearchDir 把 dir 加入 DLL 搜索路径。
//
// wireguard/tun 用普通 LoadLibrary("wintun.dll") 加载 dll（不带
// LOAD_LIBRARY_SEARCH_USER_DIRS），所以 AddDllDirectory 对它无效——
// 必须用 SetDllDirectory 把 dir 放进标准搜索顺序。系统 dll（kernel32 等）
// 由 KnownDLLs 机制保证，不受影响。
func addDLLSearchDir(dir string) error {
	dirPtr, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if r, _, e2 := procSetDllDir.Call(uintptr(unsafe.Pointer(dirPtr))); r == 0 {
		return fmt.Errorf("SetDllDirectory(%q) 失败: %v", dir, e2)
	}
	// 同时追加到新 API 的搜索集，给其它带 LOAD_LIBRARY_SEARCH_* 的调用兜底。
	procAddDllDir.Call(uintptr(unsafe.Pointer(dirPtr)))
	return nil
}

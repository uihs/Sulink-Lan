//go:build windows

package gui

import (
	"golang.org/x/sys/windows"
)

// isElevated 检测当前进程是否具有管理员权限。
//
// 实现方式：尝试打开当前进程的 Token 并查询其提权状态。
// 相比「写注册表 HKLM」「创建系统目录文件」等探测法，这种方式无副作用。
func isElevated() bool {
	var sid *windows.SID
	// WinBuiltinAdministratorsSid 无需真实 SID，仅用于分配
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

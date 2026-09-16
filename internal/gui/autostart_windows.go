//go:build windows

package gui

// 开机自启：写当前用户注册表 HKCU\Software\Microsoft\Windows\CurrentVersion\Run。
//
// 为什么用注册表而非启动文件夹：
//   - 不需要管理员权限，且用户可在「任务管理器 → 启动」中看到并禁用，行为可预期；
//   - 启动文件夹方式易被安全软件误判，且路径含空格时快捷方式处理更麻烦。
import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// runKeyPath 自启注册表项位置。
const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// valueName 注册表值名，与安装时的 AppId 保持一致。
const valueName = "SulinkLan"

// setAutoStart 开启/关闭开机自启。
func setAutoStart(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if !on {
		// 值不存在时 DeleteValue 返回 ErrNotExist，视为成功
		if err := k.DeleteValue(valueName); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	// 以最小化参数启动：自启时不弹主窗口打扰用户，托盘图标即可
	cmd := fmt.Sprintf(`"%s" -autostart`, exe)
	return k.SetStringValue(valueName, cmd)
}

//go:build linux

package hwid

import (
	"os"
	"strings"
)

// machineIDPaths 按优先级排列的系统机器标识文件。
//
// /etc/machine-id 是 systemd 时代的标准位置；/var/lib/dbus/machine-id 是
// 更早的 D-Bus 位置，一些老发行版或未用 systemd 的系统只有后者。
func machineIDPaths() []string {
	return []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
}

// rawMachineID 读取系统机器标识。
func rawMachineID() (string, bool) {
	for _, p := range machineIDPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, true
		}
	}
	return "", false
}

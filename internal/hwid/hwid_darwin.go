//go:build darwin

package hwid

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// rawMachineID 读取 macOS 的硬件 UUID（IOPlatformUUID）。
//
// 为什么走外部命令而不是 sysctl：IOPlatformUUID 只由 IORegistry 暴露，
// 标准库没有对应接口，纯 Go 取它要么上 cgo（本项目刻意保持 CGO_ENABLED=0，
// 见构建约定），要么解析 ioreg 的输出。后者多一次进程创建，
// 但只在进程内第一次用到时执行一次，代价可以接受。
func rawMachineID() (string, bool) {
	// 加超时：ioreg 正常在毫秒级返回，卡住说明系统有问题，
	// 不该让客户端连接流程一起挂在这里。
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", false
	}
	return parseIOPlatformUUID(string(out))
}

// parseIOPlatformUUID 从 ioreg 输出里提取 IOPlatformUUID 的值。
//
// 输出形如：  "IOPlatformUUID" = "0A1B2C3D-...-F0"
// 单独拆出来是为了能脱离 macOS 做单元测试——本项目的 CI 与开发机都不一定是 mac。
func parseIOPlatformUUID(out string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "IOPlatformUUID")
		if i < 0 {
			continue
		}
		rest := line[i+len("IOPlatformUUID"):]
		j := strings.Index(rest, "=")
		if j < 0 {
			continue
		}
		v := strings.TrimSpace(rest[j+1:])
		v = strings.Trim(v, `"`)
		if v != "" {
			return v, true
		}
	}
	return "", false
}

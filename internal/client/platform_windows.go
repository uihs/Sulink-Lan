//go:build windows

package client

import "log"

// PreparePlatform 做 Windows 平台特有的启动准备：释放内嵌的 wintun.dll。
//
// 为什么放在这里而不是 main：命令行客户端与图形客户端都需要它，
// 且失败时的处理方式一致——直接报错退出，避免用户看到
// "Failed to load wintun.dll" 这种无从下手的底层错误。
func PreparePlatform() (func(), error) {
	path, err := EnsureWintunDLL()
	if err != nil {
		return nil, err
	}
	log.Printf("[client] 虚拟网卡驱动就绪: %s", path)
	return func() {}, nil
}

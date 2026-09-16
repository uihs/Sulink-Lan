//go:build windows

package hwid

import "golang.org/x/sys/windows/registry"

// rawMachineID 读取 Windows 安装时生成的 MachineGuid。
//
// 注册表里唯一能标识「这一次 Windows 安装」的值就是它：重装系统会变，
// 换硬件不会变——正是租约需要的粒度。
//
// 必须带 WOW64_64KEY：MachineGuid 位于 64 位视图下，32 位进程默认会被
// 重定向到 Wow6432Node，读不到值，然后静默退化成「随机标识」分支，
// 表现为「32 位客户端每次重装都换 IP」这种只在特定构建下出现的怪现象。
func rawMachineID() (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", false
	}
	return v, true
}

//go:build windows

package client

import (
	"log"
	"os/exec"
	"strings"
)

// removeStaleSulinkAdapters 清理残留的 wintun 虚拟网卡和残留的网络配置文件名。
//
// 背景一（网卡）：wintun 建卡时若 "Sulink Lan" 这个连接名已存在（哪怕是上次崩溃
// 没释放的孤儿网卡），它不会复用，而是自动改用 "Sulink Lan 1"、"Sulink Lan 2"……
// 反复异常退出后系统里就堆出 "Sulink Lan 121" 这种网卡。真正占着裸名的往往是那张
// 裸名孤儿网卡，只删带序号项永远删不掉它，所以这里把所有 baseName 开头的网卡都卸载。
//
// 背景二（网络配置文件名）：即使网卡名已经固定为 "Sulink Lan"，每次 wintun 新建的
// 网卡 GUID 不同，Windows 就把它当作一个"新网络"，在 NetworkList\Profiles 里
// 建一个 ProfileName。因为已经有 1..127 个叫 "Sulink Lan N" 的旧配置文件，
// 新的就被命名成 "Sulink Lan 128"——网络和共享中心因此显示 "Sulink Lan 128"，
// 看着像网卡名一直在涨，其实涨的是网络配置文件名。这里把这些残留的 Sulink 网络
// 配置文件（和对应的 Signatures 项）一并删掉，新网络就会叫回 "Sulink Lan"。
//
// 本函数在 OpenTun 里、本进程网卡还没创建之前调用，删掉的都是上次留下的垃圾。
// wintun 0.14.1 没有按网卡删除的导出函数，网卡卸载走系统自带 pnputil。
// 本函数失败不影响建卡，只记录日志。
func removeStaleSulinkAdapters(baseName string) {
	// 匹配裸名 "Sulink Lan" 和带序号 "Sulink Lan 123"。
	ps := `
$ErrorActionPreference='SilentlyContinue'
$base = '__BASE__'

# 1) 卸载残留网卡（裸名 + 带序号）
$rx = '^' + [regex]::Escape($base) + '(\s+\d+)?$'
$devs = Get-CimInstance Win32_NetworkAdapter |
  Where-Object { $_.NetConnectionID -and ($_.NetConnectionID -match $rx) -and $_.PNPDeviceID }
foreach ($d in $devs) {
  $r = & pnputil /remove-device "$($d.PNPDeviceID)" 2>&1 | Out-String
  if ($LASTEXITCODE -eq 0) { Write-Output ("ADAPTER REMOVED: " + $d.NetConnectionID) }
  else { Write-Output ("ADAPTER FAIL: " + $d.NetConnectionID + " " + (($r -replace "\s+"," ").Substring(0, [Math]::Min(80, $r.Length)))) }
}

# 2) 清理残留的网络配置文件名（NetworkList\Profiles + Signatures）
$profs = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
Get-ChildItem $profs -ErrorAction SilentlyContinue | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
  if ($p.ProfileName -and ($p.ProfileName -match $rx)) {
    $n = $p.ProfileName
    Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output ("PROFILE REMOVED: " + $n)
  }
}
$sigs = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures"
Get-ChildItem $sigs -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
  if ($p.ProfileName -and ($p.ProfileName -match $rx)) {
    Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
  }
}
`
	ps = strings.ReplaceAll(ps, "__BASE__", baseName)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	// 隐藏控制台窗口，避免连接时闪黑窗。
	hideConsoleWindow(cmd)
	out, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				log.Printf("[client] 清理残留: %s", line)
			}
		}
	}
	if err != nil {
		log.Printf("[client] 清理残留命令返回非零（忽略）: %v", err)
	}
}

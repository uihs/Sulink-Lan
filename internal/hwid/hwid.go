// Package hwid 提供本机的稳定设备标识（HWID）。
//
// 用途：服务端按设备标识发放 IP 租约，让同一台设备每次上线都拿回同一个虚拟 IP。
// 因此这里要的不是「唯一」而是「**稳定**」——同一个进程、同一次系统安装，
// 重启一百次也必须算出同一个值。
//
// 取值优先级：
//
//  1. 平台机器标识：Windows 读注册表 MachineGuid，Linux 读 /etc/machine-id，
//     macOS 读 IOPlatformUUID。它们由操作系统在安装时生成，天然稳定，
//     且不依赖本程序的数据目录——用户重装 Sulink Lan 也还是同一台设备。
//  2. 上述都取不到时（精简容器、权限受限、未知平台），生成一个随机标识
//     持久化到配置目录。代价是删掉配置文件就换了身份，与 DHCP 客户端
//     标识的行为一致，可接受。
//
// 无论哪种来源，最终都经 SHA-256 截断后使用，不把原始机器标识发给服务端：
// 原始 MachineGuid / machine-id 是跨服务通用的机器指纹，一旦泄露，
// 别人可以拿它去别的系统里关联出「这是同一台机器」。服务端只需要一个
// 稳定且唯一的字符串，没有任何理由知道它背后是什么。
package hwid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"sulink-lan/internal/config"
)

// idFileName 兜底标识的持久化文件名（位于客户端配置目录内）。
const idFileName = "hwid"

// salt 参与哈希的固定前缀，用于把本标识与「同一机器在其他服务里的标识」区分开。
const salt = "sulink-lan/hwid/v1|"

// IDLen 返回值的十六进制字符数（16 字节 = 128 位，碰撞概率可忽略）。
const IDLen = 32

var (
	once      sync.Once
	cached    string
	cachedErr error
)

// ID 返回本机稳定设备标识：32 位小写十六进制字符串。
//
// 结果在进程内缓存：它在每次连接时都要用，而平台查询（读注册表 / 起子进程）
// 比一次哈希贵得多，且结果本就不会变。
func ID() (string, error) {
	once.Do(func() { cached, cachedErr = compute(rawMachineID, idPath) })
	return cached, cachedErr
}

// compute 是 ID 的纯逻辑部分：优先用平台机器标识，取不到才退回持久化随机值。
//
// 两个来源都以函数注入，测试才能在不碰真实注册表、不污染真实配置目录的前提下
// 覆盖「有平台标识」与「无平台标识」两条分支。
func compute(machineID func() (string, bool), path func() (string, error)) (string, error) {
	if raw, ok := machineID(); ok {
		if s := strings.TrimSpace(raw); s != "" {
			return fingerprint(s), nil
		}
	}
	return persistedRandom(path)
}

// persistedRandom 读取（不存在则生成并写入）配置目录里的随机标识。
func persistedRandom(path func() (string, error)) (string, error) {
	p, err := path()
	if err != nil {
		return "", err
	}
	// 读得到就用：文件内容为空（例如被意外清空）时按「不存在」处理，
	// 否则空字符串会被当成一个合法的设备标识，让所有此类机器共用一个身份。
	if b, err := os.ReadFile(p); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return fingerprint(s), nil
		}
	}
	// 256 位随机，远超「同一服务端下不重复」所需的强度。
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成设备标识失败: %w", err)
	}
	raw := hex.EncodeToString(buf)
	// 先写文件再返回：写失败就必须报错。若这里悄悄返回一个内存里的随机值，
	// 设备每次重启都会换身份，租约永远绑不上，而故障现象是「IP 老是变」——
	// 极难联想到是这里没写成功。
	if err := os.WriteFile(p, []byte(raw+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("写入设备标识失败(%s): %w", p, err)
	}
	return fingerprint(raw), nil
}

// idPath 兜底标识的文件路径（与客户端配置同目录）。
func idPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, idFileName), nil
}

// fingerprint 把任意原始标识映射成固定长度的对外标识。
func fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(salt + raw))
	return hex.EncodeToString(sum[:16])
}

//go:build !windows && !linux && !darwin

package hwid

// rawMachineID 在未适配的平台上恒返回 false，让 compute 走持久化随机标识。
//
// 这里刻意不猜、不硬编造一个值：拿不到系统级稳定标识时，
// 老老实实退回「随机但持久」比伪造一个看起来像机器码的字符串更诚实，
// 前者只是身份跟着配置目录走，后者会让服务端把不同机器认成同一台。
func rawMachineID() (string, bool) {
	return "", false
}

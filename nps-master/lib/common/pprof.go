package common

import (
	"net/http"
	_ "net/http/pprof" // 注册 /debug/pprof/* 处理器

	"github.com/astaxie/beego/logs"
)

// pprofIP / pprofPort 由服务端在加载配置后注入（见 internal/npsembed）。
//
// 为什么不用 beego.AppConfig 读：lib/common 被客户端依赖
// （nps/client → lib/conn → lib/common），在包里 import beego **根包**
// 会把整个框架链进客户端二进制（实测约 2-3MB，含 session / grace /
// toolbox / context / autocert 等），而客户端根本不用 pprof。
// 注意只引 beego/logs 是安全的——那是独立小包，不含框架。
//
// 语义与原来等价：两者都为空时不启动监听。
// 另注：Sulink Lan 自动生成的 NPS 配置模板里并没有 pprof_ip / pprof_port，
// 所以实际恒为空、监听不会启动——保持这一行为即可。
var (
	pprofIP   string
	pprofPort string
)

// SetPProf 由服务端注入 pprof 监听地址与端口（任一为空即不启用）。
func SetPProf(ip, port string) {
	pprofIP, pprofPort = ip, port
}

func InitPProfFromFile() {
	if len(pprofIP) > 0 && len(pprofPort) > 0 && IsPort(pprofPort) {
		runPProf(pprofIP + ":" + pprofPort)
	}
}

func InitPProfFromArg(arg string) {
	if len(arg) > 0 {
		runPProf(arg)
	}
}

func runPProf(ipPort string) {
	go func() {
		_ = http.ListenAndServe(ipPort, nil)
	}()
	logs.Info("PProf debug listen on", ipPort)
}

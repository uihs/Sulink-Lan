package common

// AddOriginHeader 控制 ChangeHostAndHeader 是否写入 X-Forwarded-For / X-Real-IP。
//
// 为什么不用 beego.AppConfig 直接读：lib/common 被客户端依赖
// （nps/client → lib/conn → lib/common），而在包里 import beego 根包
// 会把整个 beego 框架链进客户端二进制（实测约 2-3MB，含 session / grace /
// toolbox / context / autocert 等），客户端却完全不用这些。
// 本次排查中它就是客户端体积的第二大来源（仅次于 NPS Web 控制台静态资源）。
//
// 因此改为包级变量，由真正需要它的**服务端**在加载 NPS 配置后赋值
// （见 internal/npsembed 的 LoadNpsConf）。客户端不设置，保持默认 false，
// 而客户端本来也不会走到 ChangeHostAndHeader（只被 server/proxy 调用）。
var AddOriginHeader = false

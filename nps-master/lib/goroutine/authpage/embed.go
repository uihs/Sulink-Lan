// Package authpage 只内嵌 IP 白名单认证页（auth.html）这**一个**文件。
//
// 为什么不直接复用 ehang.io/nps/web：
// 那个包的 //go:embed static views 会把 NPS 服务端 Web 控制台的全部前端资源
// （css/js/webfonts 共约 3MB）打进二进制，而本处只需要其中 6KB 的 auth.html。
// 客户端也链到本包（nps/client → lib/conn → lib/goroutine），
// 却完全不使用那套控制台界面，白付 3MB 体积。
//
// 内容与 web/static/page/auth.html 保持一致；改动认证页时两处都要同步，
// 但这是刻意的取舍——用一个 6KB 的文件换掉 3MB 的依赖。
package authpage

import _ "embed"

// AuthHTML 是 IP 白名单认证页的完整 HTML，内含 ${ip} 占位符待替换。
//
//go:embed auth.html
var AuthHTML []byte

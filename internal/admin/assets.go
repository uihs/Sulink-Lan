package admin

import _ "embed"

// pageHTML 是内嵌的管理页。
//
// 用 go:embed 而不是外部文件：服务端交付形态是一个二进制（很多部署就是
// scp 一个 exe 上去），页面若落在磁盘上，漏拷一个文件管理页就 404。
// 嵌进去之后「一个文件即完整服务端」。
//
//go:embed page.html
var pageHTML string

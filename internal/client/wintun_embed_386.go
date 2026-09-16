//go:build windows && 386

package client

import _ "embed"

// wintunDLL 是 386 架构的 wintun.dll（官方 0.14.1 发行版，MIT 许可）。
//
//go:embed assets/wintun/wintun-386.dll
var wintunDLL []byte

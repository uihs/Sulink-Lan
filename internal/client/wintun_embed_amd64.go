//go:build windows && amd64

package client

import _ "embed"

// wintunDLL 是 amd64 架构的 wintun.dll（官方 0.14.1 发行版，MIT 许可）。
//
//go:embed assets/wintun/wintun-amd64.dll
var wintunDLL []byte

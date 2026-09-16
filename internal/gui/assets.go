//go:build windows

package gui

import _ "embed"

// indexHTML 是内嵌的前端页面（Vue-free，原生 JS）。
// 编译期嵌入二进制，运行时无需任何外部文件——这是「开箱即用」的基础。
//
//go:embed assets/index.html
var indexHTML string

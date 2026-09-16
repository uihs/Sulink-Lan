//go:build windows

package gui

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	webview "github.com/jchv/go-webview2"

	"sulink-lan/internal/config"
)

// Version 返回客户端版本号。
func Version() string { return appVersion }

// Options 启动选项。
type Options struct {
	Debug bool
}

// RunWithOptions 按选项启动 GUI。
func RunWithOptions(opts Options) error {
	app, err := New()
	if err != nil {
		return err
	}
	w := webview.New(opts.Debug)
	app.w = w
	defer w.Destroy()

	w.SetTitle("Sulink Lan")
	// 窗口偏小是刻意的：客户端多数时间只是缩在角落挂着看是否在线，
	// 之前 920x640 在 1366x768 的笔记本上会顶到任务栏。最小尺寸按侧栏 180px
	// + 内容区最小可用宽度估算，再小就会让地址卡里的 IP 被省略号截断。
	w.SetSize(820, 560, webview.HintNone)
	w.SetSize(680, 480, webview.HintMin)

	// 绑定 JS 桥接（JS 端调用 goXxx 命名）
	w.Bind("goGetState", app.GetStateJSON)
	w.Bind("goConnect", func() string { return app.Connect() })
	w.Bind("goDisconnect", func() string { return app.Disconnect() })
	w.Bind("goSaveConfig", app.SaveConfig)
	w.Bind("goSetAutoStart", app.SetAutoStart)
	w.Bind("goClearLogs", app.ClearLogs)
	w.Bind("goCopyText", app.CopyText)
	w.Bind("goQuit", app.Quit)

	// 加载内嵌 HTML
	w.SetHtml(indexHTML)

	w.Run()
	return nil
}

// DefaultLogPath 返回默认日志文件路径。
func DefaultLogPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "client.log"), nil
}

// Fatal 弹出错误对话框并退出。
func Fatal(title, msg string) {
	t, _ := syscall.UTF16PtrFromString(title)
	c, _ := syscall.UTF16PtrFromString(msg)
	user32 := syscall.NewLazyDLL("user32.dll")
	user32.NewProc("MessageBoxW").Call(0,
		uintptr(unsafe.Pointer(c)),
		uintptr(unsafe.Pointer(t)),
		0x0|0x10)
	os.Exit(1)
}

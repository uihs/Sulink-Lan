// Package npsembed 把 NPS 服务端嵌入 Sulink Lan 服务端进程。
//
// 设计：
//   - NPS 自己的配置/数据放在 server 可写目录下的 nps-data/，
//     里面是 conf/nps.conf 和 NPS 的 clients.json/hosts.json 等。
//   - 启动后 NPS 会在 bridge_port（npc 客户端连接）和 web_port
//     （NPS 自己的 Web 管理面板）上监听。
//   - 与 Sulink Lan 原有的虚拟网段（9000/TCP+UDP）互不干扰。
package npsembed

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ehang.io/nps/bridge"
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/crypt"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/server"
	"ehang.io/nps/server/connection"
	"ehang.io/nps/server/tool"
	"ehang.io/nps/web/routers"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
)

// defaultNpsConf 与 nps-master/cmd/nps/nps.go 中的模板保持一致，
// 但端口默认错开 Sulink Lan：bridge 8024、web 8081。
const defaultNpsConf = `http_proxy_ip=0.0.0.0
http_proxy_port=80
https_proxy_port=443
show_http_proxy_port=true

bridge_type=tcp
bridge_port=8024
bridge_ip=0.0.0.0

public_vkey=

flow_store_interval=1

log_level=6
log_path=nps.log

web_host=
web_username=admin
web_password=
web_port=8081
web_ip=0.0.0.0
web_base_url=
web_open_ssl=false
web_cert_file=conf/server.pem
web_key_file=conf/server.key

auth_key=
auth_crypt_key =

allow_user_login=true
allow_user_register=false
allow_user_change_username=true

allow_flow_limit=true
allow_rate_limit=true
allow_tunnel_num_limit=true
allow_local_proxy=false
allow_connection_num_limit=true
allow_multi_ip=true
system_info_display=true

http_add_origin_header=true

http_cache=false
http_cache_length=100

disconnect_timeout=60

open_captcha=false

tls_enable=false
tls_bridge_port=8025
`

// DeviceInfo 在线设备信息（供 NPS 管理页下拉选择）。
type DeviceInfo struct {
	Hwid string `json:"hwid"`
	Name string `json:"name"`
	VIP  string `json:"vip"`
}

// DeviceLister 返回当前在线设备列表。
type DeviceLister func() []DeviceInfo

var globalDeviceLister DeviceLister

// SetDeviceLister 注册设备列表提供者。
func SetDeviceLister(fn DeviceLister) {
	globalDeviceLister = fn
}

// EnsureClientByVkey 确保 NPS 中存在一个 vkey 对应的 NPC 客户端。
// 如果已存在则不重复创建。用于 Sulink Lan 客户端连上后自动注册 NPC 身份。
func EnsureClientByVkey(vkey, remark string) error {
	db := file.GetDb()
	if db == nil {
		return nil // NPS 未启动
	}
	// 遍历查找是否已存在
	list, _ := db.GetClientList(0, 9999, "", "id", "asc", 0)
	for _, c := range list {
		if c.VerifyKey == vkey {
			return nil // 已存在
		}
	}
	c := file.NewClient(vkey, false, false)
	c.Remark = remark
	return db.NewClient(c)
}

// Start 在给定数据目录下启动 NPS 服务端。
// dataDir 必须是 server 进程可写的目录（如 ./nps-data）。
// 函数在后台 goroutine 里跑，不阻塞调用方。
// 返回的 webPort 是实际监听的 NPS Web 面板端口（供日志/提示用）。
func Start(dataDir string) (webPort int, err error) {
	return StartWithDevices(dataDir, nil)
}

// StartWithDevices 同 Start，但注入设备列表回调。
func StartWithDevices(dataDir string, lister DeviceLister) (webPort int, err error) {
	if lister != nil {
		globalDeviceLister = lister
	}
	if err = os.MkdirAll(dataDir, 0o755); err != nil {
		return 0, err
	}
	confDir := filepath.Join(dataDir, "conf")
	if err = os.MkdirAll(confDir, 0o755); err != nil {
		return 0, err
	}

	// 让 NPS 所有 GetRunPath/GetAppPath 都落到 dataDir。
	common.ConfPath = dataDir

	confPath := filepath.Join(confDir, "nps.conf")
	if _, statErr := os.Stat(confPath); os.IsNotExist(statErr) {
		webPassword := crypt.GetRandomString(8)
		authKey := crypt.GetRandomString(8)
		authCryptKey := crypt.GetRandomString(16)
		content := strings.Replace(defaultNpsConf, "web_password=\n", "web_password="+webPassword+"\n", 1)
		content = strings.Replace(content, "auth_key=\n", "auth_key="+authKey+"\n", 1)
		content = strings.Replace(content, "auth_crypt_key =\n", "auth_crypt_key ="+authCryptKey+"\n", 1)
		if w, werr := os.Create(confPath); werr == nil {
			w.WriteString(content)
			w.Close()
		}
		logs.Info("NPS 自动生成配置:", confPath)
		logs.Info("NPS Web 用户名 admin，密码:", webPassword)
	}

	if err = beego.LoadAppConfig("ini", confPath); err != nil {
		return 0, err
	}

	// 把 lib/common 需要读的两项配置注入进去。
	//
	// 背景：lib/common 原来直接 import beego 根包读 AppConfig，但该包被客户端
	// 依赖（nps/client → lib/conn → lib/common），于是整个 beego 框架被链进
	// 客户端二进制（约 2-3MB）。改为在这里（真正的服务端入口）读一次再注入，
	// 客户端不再依赖 beego，行为完全不变。
	common.SetPProf(
		beego.AppConfig.String("pprof_ip"),
		beego.AppConfig.String("pprof_port"),
	)
	if addOrigin, err := beego.AppConfig.Bool("http_add_origin_header"); err == nil {
		common.AddOriginHeader = addOrigin
	}

	level := beego.AppConfig.DefaultString("log_level", "6")
	logs.Reset()
	_ = logs.SetLogger(logs.AdapterConsole, `{"level":`+level+`,"color":false}`)
	logs.EnableFuncCallDepth(true)
	logs.SetLogFuncCallDepth(3)

	bridge.ServerTlsEnable = beego.AppConfig.DefaultBool("tls_enable", false)

	// Web 路由 + beego HTTP 监听
	routers.Init()

	// Sulink Lan 扩展 API：在线设备列表
	beego.Router("/api/sulink/devices", &sulinkController{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logs.Error("nps web run panic:", r)
			}
		}()
		beego.Run()
	}()

	connection.InitConnectionService()
	crypt.InitTls()
	tool.InitAllowPort()
	tool.StartSystemInfo()

	bridgePort, err := beego.AppConfig.Int("bridge_port")
	if err != nil {
		bridgePort = 8024
	}
	timeout, err := beego.AppConfig.Int("disconnect_timeout")
	if err != nil || timeout <= 0 {
		timeout = 60
	}
	task := &file.Tunnel{Mode: "webServer"}
	go server.StartNewServer(bridgePort, task, beego.AppConfig.String("bridge_type"), timeout)

	wp, _ := beego.AppConfig.Int("web_port")
	if wp <= 0 {
		wp = 8081
	}
	_ = strconv.Itoa(bridgePort)
	logs.Info("NPS 已启动: bridge :%d, web :%d", bridgePort, wp)
	return wp, nil
}

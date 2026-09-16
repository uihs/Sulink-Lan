package npsembed

import (
	"encoding/json"
	"net/http"

	"github.com/astaxie/beego"
)

// sulinkController 提供 Sulink Lan 扩展 API。
type sulinkController struct {
	beego.Controller
}

// ListDevices 返回在线设备列表 JSON。
func (c *sulinkController) ListDevices() {
	c.Ctx.Output.SetStatus(http.StatusOK)
	c.Ctx.Output.Header("Content-Type", "application/json; charset=utf-8")
	if globalDeviceLister == nil {
		_, _ = c.Ctx.ResponseWriter.Write([]byte("[]"))
		return
	}
	list := globalDeviceLister()
	if list == nil {
		list = []DeviceInfo{}
	}
	// 手动序列化避免引入额外依赖
	c.writeJSON(list)
}

func (c *sulinkController) writeJSON(v any) {
	b, _ := json.Marshal(v)
	_, _ = c.Ctx.ResponseWriter.Write(b)
}

func (c *sulinkController) Get() {
	c.ListDevices()
}

func (c *sulinkController) Post() {
	c.ListDevices()
}

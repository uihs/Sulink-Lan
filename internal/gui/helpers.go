// Package gui 提供图形界面客户端（Windows）。
//
// 本文件放平台无关的纯函数逻辑，便于在任意平台做单元测试。
package gui

import (
	"fmt"
	"net"
	"strconv"

	"sulink-lan/internal/config"
)

// validatePartial 宽松校验：只拦截明显写错的值（服务器格式），
// 不强制要求填全——用户可能先配一半就去填别的，此时不该报错。
func validatePartial(c config.Config) error {
	if c.Server != "" {
		normalized := config.NormalizeServerAddr(c.Server)
		host, port, err := net.SplitHostPort(normalized)
		if err != nil {
			return fmt.Errorf("服务器地址格式不正确: %s", c.Server)
		}
		if host == "" {
			return fmt.Errorf("服务器地址缺少主机名或 IP")
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("服务器端口需为 1-65535 之间的数字")
		}
	}
	return nil
}

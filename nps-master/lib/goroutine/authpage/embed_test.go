package authpage

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAuthHTMLMatchesWebCopy 守住 authpage/auth.html 与
// web/static/page/auth.html 的一致性。
//
// 为什么要这个测试：为了避免把 3MB 的 Web 控制台资源拖进客户端，
// 认证页被复制成了两份（那份是服务端控制台用的，这份是隧道转发用的）。
// 两份内容不同步会导致「隧道转发时看到的认证页」和「控制台里看到的」不一致，
// 而这种差异只在特定路径下才暴露，很难靠人发现。
//
// 所以把它变成一条会失败的测试：改了其中一份而忘了另一份，测试立刻报错。
func TestAuthHTMLMatchesWebCopy(t *testing.T) {
	// 从 authpage/ 上溯到 nps-master/，再拼出 web 那份的路径。
	src := filepath.Join("..", "..", "..", "web", "static", "page", "auth.html")
	want, err := os.ReadFile(src)
	if err != nil {
		// 仓库结构变化（如模块被单独 vendored 出去）时不算失败：
		// 这个测试的意义是「两份在同一个仓库里时必须一致」，
		// 找不到另一份就说明这个前提不成立。
		t.Skipf("未找到 web 侧副本（%s），跳过一致性检查: %v", src, err)
	}
	if string(want) != string(AuthHTML) {
		t.Fatalf("auth.html 两份副本内容不一致：\n"+
			"  本包   : lib/goroutine/authpage/auth.html (%d 字节)\n"+
			"  web 侧 : web/static/page/auth.html (%d 字节)\n"+
			"改认证页时两份都要同步（原因见本包 embed.go 的注释）",
			len(AuthHTML), len(want))
	}
}

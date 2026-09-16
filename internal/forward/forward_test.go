package forward

import "testing"

func TestParseValid(t *testing.T) {
	r, err := Parse("8080=192.168.1.5:80")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.VPort != 8080 || r.TargetPort != 80 {
		t.Fatalf("端口解析错误: %+v", r)
	}
	if got := ipString(r.TargetIP); got != "192.168.1.5" {
		t.Fatalf("目标 IP 解析错误: %s", got)
	}
}

// TestParseRejectsBad 逐项覆盖非法输入。
//
// 特别包含「虚拟端口为 0」：早期实现用 fmt.Sscanf("%d", &uint16) 解析，
// 0 能顺利通过，于是配置里多出一条永远匹配不到的规则，
// 用户只会觉得「填了没反应」。
func TestParseRejectsBad(t *testing.T) {
	cases := []struct {
		in   string
		desc string
	}{
		{"8080", "缺少 ="},
		{"=192.168.1.5:80", "虚拟端口为空"},
		{"abc=192.168.1.5:80", "虚拟端口不是数字"},
		{"0=192.168.1.5:80", "虚拟端口为 0"},
		{"70000=192.168.1.5:80", "虚拟端口越界"},
		{"8080=192.168.1.5", "目标缺少端口"},
		{"8080=not-an-ip:80", "目标 IP 非法"},
		{"8080=192.168.1.5:0", "目标端口为 0"},
		{"8080=192.168.1.5:70000", "目标端口越界"},
		{"8080=192.168.1.5:80=extra", "多余的 = 导致目标非法"},
		{"", "空串"},
	}
	for _, c := range cases {
		if _, err := Parse(c.in); err == nil {
			t.Fatalf("应当拒绝（%s）: %q", c.desc, c.in)
		}
	}
}

// TestParseListFailsWhole 一条坏规则必须让整批失败，不能静默丢弃。
func TestParseListFailsWhole(t *testing.T) {
	_, err := ParseList([]string{"8080=192.168.1.5:80", "坏规则"})
	if err == nil {
		t.Fatal("含坏规则时应当整体报错")
	}
	ok, err := ParseList([]string{"8080=192.168.1.5:80", "9000=192.168.1.6:9000"})
	if err != nil {
		t.Fatalf("全部合法时不应报错: %v", err)
	}
	if len(ok) != 2 {
		t.Fatalf("应解析出 2 条: %d", len(ok))
	}
}

func TestSplitConfig(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"8080=192.168.1.5:80", 1},
		{"8080=192.168.1.5:80\n9000=192.168.1.6:9000", 2},
		{"8080=192.168.1.5:80\r\n9000=192.168.1.6:9000", 2},
		{"8080=192.168.1.5:80,9000=192.168.1.6:9000", 2},
		{"8080=192.168.1.5:80;9000=192.168.1.6:9000", 2},
		{"8080=192.168.1.5:80  9000=192.168.1.6:9000", 2},
		{"\n\n8080=192.168.1.5:80\n\n\n", 1},
		{"", 0},
		{"   \n\t ", 0},
		{",,,", 0},
	}
	for _, c := range cases {
		if got := SplitConfig(c.in); len(got) != c.want {
			t.Fatalf("SplitConfig(%q) = %v（%d 条），期望 %d 条", c.in, got, len(got), c.want)
		}
	}
}

// TestParseConfigMulti 下发配置里的多行文本能整段解析。
func TestParseConfigMulti(t *testing.T) {
	rules, err := ParseConfig("8080=192.168.1.5:80\n19132=192.168.1.9:19132")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("应解析出 2 条: %d", len(rules))
	}
	// 空配置表示「没有规则」，必须是正常返回而非报错
	empty, err := ParseConfig("")
	if err != nil {
		t.Fatalf("空配置不应报错: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("空配置应得到 0 条: %d", len(empty))
	}
}

// TestParseSetRejectsDuplicatePorts 同一组里虚拟端口重复必须整体报错。
//
// 客户端的规则表按虚拟端口建索引，重复端口会互相覆盖，
// 表现为「配了两条只有一条生效」且毫无提示。
func TestParseSetRejectsDuplicatePorts(t *testing.T) {
	if _, err := ParseSet([]string{"8080=192.168.1.5:80", "8080=192.168.1.6:80"}); err == nil {
		t.Fatal("重复虚拟端口应被拒绝")
	}
	// 不同端口、同一目标，是合法配置
	ok, err := ParseSet([]string{"8080=192.168.1.5:80", "8081=192.168.1.5:80"})
	if err != nil {
		t.Fatalf("不同虚拟端口不应报错: %v", err)
	}
	if len(ok) != 2 {
		t.Fatalf("应解析出 2 条: %d", len(ok))
	}
	// 单条坏规则同样整体失败（继承 ParseList 的行为）
	if _, err := ParseSet([]string{"8080=192.168.1.5:80", "坏规则"}); err == nil {
		t.Fatal("含坏规则时应整体报错")
	}
	// 空集合合法
	if _, err := ParseSet(nil); err != nil {
		t.Fatalf("空集合不应报错: %v", err)
	}
}

// TestStringRoundTrip String 与 Parse 必须互为逆运算——
// 管理页会把规则回显成文本让管理员再编辑，回显格式一旦无法解析，
// 「打开页面再点保存」就会把好规则改成坏规则。
func TestStringRoundTrip(t *testing.T) {
	for _, in := range []string{
		"8080=192.168.1.5:80",
		"19132=10.0.0.9:19132",
		"443=172.16.31.4:8443",
	} {
		r, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got := r.String(); got != in {
			t.Fatalf("回显不一致: %q -> %q", in, got)
		}
		again, err := Parse(r.String())
		if err != nil {
			t.Fatalf("回显结果无法再解析: %v", err)
		}
		if again != r {
			t.Fatalf("往返后规则变了: %+v -> %+v", r, again)
		}
	}
}

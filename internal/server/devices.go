package server

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"sulink-lan/internal/forward"
	"sulink-lan/internal/protocol"
)

// LeaseDuration IP 租约时长：31 天。
//
// 为什么是 31 天，而不是更短或永久：
//   - 太短（几小时）→ 设备出差一周回来地址已被别人用掉，用户会觉得
//     「说好的固定地址」是假的；
//   - 永久 → 设备报废、系统重装后地址永远占着，池子只增不减，
//     而且没有任何机制能安全回收（无法区分「长期离线」与「不再使用」）。
//
// 31 天是个折中：设备每月至少上线一次，地址就一直是它的；
// 连续一个月没出现，才认为这个地址可以给别人。
const LeaseDuration = 31 * 24 * time.Hour

// deviceRecord 服务端为一台设备保存的记录。
//
// 它同时承载三件事：IP 租约（VIP / ExpireAt）、穿透规则（Forward）
// 与认证凭证（DeviceID / DeviceKey，自动注册签发）。
// 合并成一条记录是因为它们都以「设备标识」为主键、都随设备走，
// 拆成多张表只会多几份需要保持同步的索引。
type deviceRecord struct {
	HWID string
	Name string
	// VIP 为 0 表示尚未分配过地址（例如只被管理员预先配了穿透规则、
	// 设备还没上线过）。这种记录不占地址池，但规则要留住。
	VIP      uint32
	ExpireAt time.Time
	// Forward 该设备的穿透规则（原始串，形如 "8080=192.168.1.5:80"）。
	// 服务端是唯一来源：客户端没有配置入口，只能执行。
	Forward []string
	// DeviceID / DeviceKey 自动注册签发的设备凭证。
	// DeviceID 是认证时客户端明文上报的索引；DeviceKey 是 32 字节随机
	// 密钥的 hex 形式，服务端存明文才能验证客户端的 HMAC 挑战应答
	// （服务端是信任根，本身持有数据面网络密钥）。
	// 设备首次自动注册后这两个字段必非空。
	DeviceID  string
	DeviceKey string
	// Blocked 封禁标记。管理员「清除凭证 / 踢下线」会把设备置为封禁：
	// 此时自动注册与凭证认证都会被拒绝，设备无法再入网；
	// 管理员在管理页「解除封禁」后恢复。这是与「见 HWID 即注册」模型配套的
	// 管理员侧闸门——否则清完凭证设备立刻凭 HWID 自动回来，按钮形同虚设。
	Blocked bool
}

// DeviceTable 设备表：设备标识 -> 记录，附 VIP 与 DeviceID 两个反向索引。
type DeviceTable struct {
	mu         sync.Mutex
	path       string // 落盘路径；为空表示只在内存中（测试用）
	byHWID     map[string]*deviceRecord
	byVIP      map[uint32]string
	byDeviceID map[string]string // DeviceID -> HWID
}

// deviceFile 设备表的落盘结构。
//
// 带 version 字段：将来若要调整结构，可以据此判断该按哪个版本解析，
// 而不是靠「字段存不存在」去猜——那种猜测在字段恰好为零值时必然出错。
type deviceFile struct {
	Version int          `json:"version"`
	Devices []deviceJSON `json:"devices"`
}

// deviceJSON 单条记录的落盘形态。
//
// VIP 存点分十进制字符串而不是整数：这个文件是给人看的（也是应急时
// 手工改的），"10.0.0.2" 一眼能懂，167772162 得换算半天。
type deviceJSON struct {
	HWID     string    `json:"hwid"`
	Name     string    `json:"name,omitempty"`
	VIP      string    `json:"vip,omitempty"`
	ExpireAt time.Time `json:"expireAt,omitempty"`
	Forward  []string  `json:"forward,omitempty"`
	// DeviceID / DeviceKey 自动注册签发的凭证。字段在 v1 文件里缺席即为空（老文件兼容）。
	DeviceID  string `json:"deviceId,omitempty"`
	DeviceKey string `json:"deviceKey,omitempty"`
	// Blocked 封禁标记（v1 文件缺席视为未封禁）。
	Blocked bool `json:"blocked,omitempty"`
}

// NewDeviceTable 创建并加载设备表。
//
// 永不返回错误：文件损坏或不可读时记日志并以空表继续运行。
// 服务端的本职是打通隧道，一份坏掉的租约文件不该让整个服务起不来——
// 最坏后果只是设备重新分配一次地址，而这是可自愈的。
func NewDeviceTable(path string) *DeviceTable {
	t := &DeviceTable{
		path:       path,
		byHWID:     make(map[string]*deviceRecord),
		byVIP:      make(map[uint32]string),
		byDeviceID: make(map[string]string),
	}
	if path == "" {
		return t
	}
	var f deviceFile
	loaded, err := readJSON(path, &f)
	if err != nil {
		log.Printf("[server] 设备表读取失败，将以空表启动（设备会重新分配地址）: %v", err)
		return t
	}
	if !loaded {
		return t
	}
	for _, d := range f.Devices {
		if d.HWID == "" {
			continue // 没有设备标识的记录无从索引，跳过
		}
		rec := &deviceRecord{HWID: d.HWID, Name: d.Name, ExpireAt: d.ExpireAt, Forward: d.Forward,
			DeviceID: d.DeviceID, DeviceKey: d.DeviceKey, Blocked: d.Blocked}
		if d.DeviceID != "" {
			// 凭证索引冲突（同一 DeviceID 出现在两条记录）时保留先加载的，
			// 文件是唯一入口，坏数据不该让整个表加载失败。
			if _, dup := t.byDeviceID[d.DeviceID]; !dup {
				t.byDeviceID[d.DeviceID] = d.HWID
			}
		}
		if d.VIP != "" {
			vip, err := protocol.IP4(d.VIP)
			if err != nil {
				log.Printf("[server] 设备表里 %s 的地址 %q 无法解析，该条记录将不占用地址", d.HWID, d.VIP)
			} else {
				rec.VIP = vip
				t.byVIP[vip] = d.HWID
			}
		}
		t.byHWID[d.HWID] = rec
	}
	return t
}

// SetCredential 为设备登记设备凭证（设备 ID + 密钥）。
//
// 设备可能还没有租约记录（从未上线），此时创建一条只含凭证的记录，
// 管理页因此能看到「已注册、未上线」的设备。同一台设备（HWID）已有
// 凭证时拒绝覆盖——自动注册路径会先查已有凭证并直接复用（见
// server.handleRegister），这里只负责「首次签发」；并发双注册时后到者
// 失败，由调用方回查复用，而不是静默换新凭证。
func (t *DeviceTable) SetCredential(hwid, name, deviceID, deviceKey string) error {
	if hwid == "" || deviceID == "" || deviceKey == "" {
		return errors.New("设备标识与凭证不能为空")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if owner, exists := t.byDeviceID[deviceID]; exists && owner != hwid {
		return fmt.Errorf("设备凭证已被其他设备使用")
	}
	rec := t.byHWID[hwid]
	if rec == nil {
		rec = &deviceRecord{HWID: hwid}
		t.byHWID[hwid] = rec
	}
	if rec.DeviceID != "" {
		return fmt.Errorf("设备 %s 已注册，如需更换凭证请先在管理页清除", shortHWID(hwid))
	}
	rec.DeviceID = deviceID
	rec.DeviceKey = deviceKey
	if name != "" {
		rec.Name = name
	}
	t.byDeviceID[deviceID] = hwid
	t.saveLocked()
	return nil
}

// DeviceByID 按设备凭证 ID 查找设备密钥（认证用）。
// 返回明文密钥（hex），未找到时返回空串。
func (t *DeviceTable) DeviceKeyByID(deviceID string) string {
	if deviceID == "" {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	hwid := t.byDeviceID[deviceID]
	if hwid == "" {
		return ""
	}
	if rec := t.byHWID[hwid]; rec != nil {
		return rec.DeviceKey
	}
	return ""
}

// Credential 返回某设备的凭证（自动注册时复用）。
// ok 为 false 表示该设备尚未注册过（调用方应为其签发新凭证）。
func (t *DeviceTable) Credential(hwid string) (deviceID, deviceKey string, ok bool) {
	if hwid == "" {
		return "", "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byHWID[hwid]
	if rec == nil || rec.DeviceID == "" {
		return "", "", false
	}
	return rec.DeviceID, rec.DeviceKey, true
}

// ClearCredential 清除设备凭证（管理页操作）。设备下次连接将认证失败，
// 随即按自动注册流程重新注册并拿回原凭证。返回是否真的清掉了什么。
func (t *DeviceTable) ClearCredential(hwid string) bool {
	if hwid == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byHWID[hwid]
	if rec == nil || rec.DeviceID == "" {
		return false
	}
	delete(t.byDeviceID, rec.DeviceID)
	rec.DeviceID = ""
	rec.DeviceKey = ""
	t.saveLocked()
	return true
}

// IsBlocked 返回该 HWID 是否被管理员封禁。
func (t *DeviceTable) IsBlocked(hwid string) bool {
	if hwid == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byHWID[hwid]
	return rec != nil && rec.Blocked
}

// Block 封禁设备：清掉它的凭证并置封禁标记。
//
// 与「只清凭证」的区别：清完凭证后自动注册路径会立刻按 HWID 把凭证发回来；
// 加上 Blocked 标记后，handleRegister 见到该 HWID 直接拒绝，设备才真的进不来。
// 凭证一并清除，是为了让它持旧凭证的 Hello 也立刻认证失败（DeviceKeyByID 查不到），
// 而不是等它自己发现注册被拒。
//
// 返回是否真的改了状态。记录不存在时（设备从未上线过）也建一条只含封禁标记的记录，
// 这样离线封禁才拦得住它将来首次注册。
func (t *DeviceTable) Block(hwid string) bool {
	if hwid == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byHWID[hwid]
	if rec == nil {
		rec = &deviceRecord{HWID: hwid}
		t.byHWID[hwid] = rec
	}
	if rec.Blocked && rec.DeviceID == "" {
		return false // 已是封禁态且无凭证，幂等
	}
	if rec.DeviceID != "" {
		delete(t.byDeviceID, rec.DeviceID)
		rec.DeviceID = ""
		rec.DeviceKey = ""
	}
	rec.Blocked = true
	t.saveLocked()
	return true
}

// Unblock 解除封禁（不清掉 IP 租约/规则，设备解除后下次上线直接恢复原凭证与地址）。
// 返回是否真的改了状态。
func (t *DeviceTable) Unblock(hwid string) bool {
	if hwid == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byHWID[hwid]
	if rec == nil || !rec.Blocked {
		return false
	}
	rec.Blocked = false
	t.saveLocked()
	return true
}

// Assign 为设备分配（或续租）虚拟 IP，返回地址与新的到期时刻。
//
// 语义是「尽量给回原地址」：
//   - 已有租约且地址仍在池子里 → 直接续期，设备拿回同一个地址；
//   - 有租约但地址已被别人占用（人工改过文件、迁移过服务器）→ 换一个地址，
//     而不是报错让设备连不上。地址变了是小事，连不上是大事。
//
// 每次调用都会把到期时间推到 now+31 天：只要设备持续上线，租约就一直续。
func (t *DeviceTable) Assign(hwid, name string, pool *IPPool, now time.Time) (uint32, time.Time, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 先回收过期租约：否则池子被一堆早已失效的地址占着，
	// 新设备会收到「地址池耗尽」这种看起来毫无道理的报错。
	t.pruneLocked(now, pool)

	rec := t.byHWID[hwid]
	if rec == nil {
		rec = &deviceRecord{HWID: hwid}
		t.byHWID[hwid] = rec
	}

	switch {
	case rec.VIP == 0:
		vip, err := pool.Alloc()
		if err != nil {
			return 0, time.Time{}, err
		}
		rec.VIP = vip
		t.byVIP[vip] = hwid

	case pool.Held(rec.VIP):
		// 地址还在自己名下，直接续期

	default:
		// 记录里有地址，但地址池里没有它：优先要回原地址，要不到就换一个
		want := rec.VIP
		if err := pool.AllocAt(want); err != nil {
			vip, err2 := pool.Alloc()
			if err2 != nil {
				return 0, time.Time{}, err2
			}
			delete(t.byVIP, want)
			rec.VIP = vip
			t.byVIP[vip] = hwid
			log.Printf("[server] 设备 %s 的原地址 %s 已不可用，改分配 %s",
				shortHWID(hwid), protocol.IP4String(want), protocol.IP4String(vip))
		}
	}

	rec.Name = name
	rec.ExpireAt = now.Add(LeaseDuration)
	t.saveLocked()
	return rec.VIP, rec.ExpireAt, nil
}

// Forward 返回该设备的穿透规则副本（无记录或没有规则时为空切片）。
func (t *DeviceTable) Forward(hwid string) []string {
	if hwid == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byHWID[hwid]
	if rec == nil {
		return nil
	}
	return append([]string(nil), rec.Forward...)
}

// SetForward 设置某设备的穿透规则（管理页调用）。
//
// 先整体校验再写入：服务端是规则的唯一入口，一条坏规则会同时影响
// 一台设备的穿透行为，与其让客户端各自报错，不如在这里拦住，
// 并把「哪一条、错在哪」直接告诉管理员。
func (t *DeviceTable) SetForward(hwid string, rules []string) error {
	if hwid == "" {
		return errors.New("缺少设备标识")
	}
	if _, err := forward.ParseSet(rules); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byHWID[hwid]
	if rec == nil {
		// 允许为尚未上线过的设备预先配置规则：管理员往往先规划好再装机器。
		rec = &deviceRecord{HWID: hwid}
		t.byHWID[hwid] = rec
	}
	rec.Forward = append([]string(nil), rules...)
	t.saveLocked()
	return nil
}

// SetIP 手工指定某设备的虚拟 IP（管理页调用）。
//
// 校验三件事：地址在可分配范围内、没被别的设备占用、设备标识存在。
// 不做「静默换一个」——管理员明确填了一个地址却拿到另一个，
// 比直接报错更让人困惑。
func (t *DeviceTable) SetIP(hwid string, vip uint32, pool *IPPool) error {
	if hwid == "" {
		return errors.New("缺少设备标识")
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	rec := t.byHWID[hwid]
	if rec == nil {
		return fmt.Errorf("设备不存在: %s", shortHWID(hwid))
	}
	if !pool.InRange(vip) {
		return fmt.Errorf("地址 %s 不可分配（须在虚拟网段内，且不能是服务器地址或广播地址）",
			protocol.IP4String(vip))
	}
	if owner, taken := t.byVIP[vip]; taken && owner != hwid {
		return fmt.Errorf("地址 %s 已分配给设备 %s", protocol.IP4String(vip), shortHWID(owner))
	}
	if rec.VIP == vip {
		return nil // 目标与现状一致，幂等返回
	}

	// 先占新地址再放旧地址：反过来的话，若新地址恰好被占，
	// 中间会出现「旧地址已放、新地址没拿到」的空档。
	if err := pool.AllocAt(vip); err != nil {
		return err
	}
	if rec.VIP != 0 {
		pool.Release(rec.VIP)
		delete(t.byVIP, rec.VIP)
	}
	rec.VIP = vip
	t.byVIP[vip] = hwid
	t.saveLocked()
	return nil
}

// Prune 回收所有已过期的租约，返回回收数量。
//
// 回收只清掉地址占用，**保留记录本身**：穿透规则是管理员配的，
// 不该因为设备一个月没上线就被悄悄删掉。设备下次上线时重新拿一个地址即可。
func (t *DeviceTable) Prune(now time.Time, pool *IPPool) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.pruneLocked(now, pool)
	if n > 0 {
		t.saveLocked()
	}
	return n
}

// pruneLocked 是 Prune 的无锁版本，调用方必须已持有 t.mu。
func (t *DeviceTable) pruneLocked(now time.Time, pool *IPPool) int {
	n := 0
	for _, rec := range t.byHWID {
		if rec.VIP == 0 || rec.ExpireAt.IsZero() || rec.ExpireAt.After(now) {
			continue
		}
		pool.Release(rec.VIP)
		delete(t.byVIP, rec.VIP)
		log.Printf("[server] 设备 %s(%s) 的地址 %s 租约已到期（%s 未上线），地址已回收",
			rec.Name, shortHWID(rec.HWID), protocol.IP4String(rec.VIP),
			now.Sub(rec.ExpireAt).Truncate(time.Hour))
		rec.VIP = 0
		rec.ExpireAt = time.Time{}
		n++
	}
	return n
}

// Snapshot 返回全部设备记录的对外快照，按虚拟地址排序（无地址的排最后）。
//
// 排序是为了管理页稳定：map 遍历顺序随机，不排的话每次刷新行序都在跳，
// 管理员想点某一行都得重新找。
func (t *DeviceTable) Snapshot(now time.Time, online func(vip uint32) bool) []LeaseInfo {
	t.mu.Lock()
	out := make([]LeaseInfo, 0, len(t.byHWID))
	for _, rec := range t.byHWID {
		li := LeaseInfo{
			HWID:       rec.HWID,
			Name:       rec.Name,
			Forward:    append([]string(nil), rec.Forward...),
			Registered: rec.DeviceID != "",
			Blocked:    rec.Blocked,
		}
		if rec.VIP != 0 {
			li.VIP = protocol.IP4String(rec.VIP)
			li.Online = online(rec.VIP)
			if !rec.ExpireAt.IsZero() {
				li.ExpireAt = rec.ExpireAt.Unix()
				li.RemainSecs = int64(rec.ExpireAt.Sub(now).Seconds())
			}
		}
		out = append(out, li)
	}
	t.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.VIP == "") != (b.VIP == "") {
			return b.VIP == "" // 有地址的排前面
		}
		if a.VIP != b.VIP {
			return a.VIP < b.VIP
		}
		return a.HWID < b.HWID
	})
	return out
}

// Len 返回记录条数（管理页指标用）。
func (t *DeviceTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byHWID)
}

// saveLocked 落盘。调用方必须已持有 t.mu。
//
// 这里确实是在持锁做磁盘 I/O，与项目里「锁内取快照、锁外发送」的约定不同。
// 之所以可以接受：设备表的改动只发生在设备上线/下线与管理页操作时（低频），
// 文件只有几十 KB，一次写入在毫秒级；换成异步落盘则会在崩溃时丢掉最近的
// 租约变更——而那正是我们要保住的东西。低频 + 小文件，同步写更划算。
func (t *DeviceTable) saveLocked() {
	if t.path == "" {
		return
	}
	f := deviceFile{Version: 1, Devices: make([]deviceJSON, 0, len(t.byHWID))}
	for _, rec := range t.byHWID {
		d := deviceJSON{HWID: rec.HWID, Name: rec.Name, Forward: rec.Forward,
			DeviceID: rec.DeviceID, DeviceKey: rec.DeviceKey, Blocked: rec.Blocked}
		if rec.VIP != 0 {
			d.VIP = protocol.IP4String(rec.VIP)
			d.ExpireAt = rec.ExpireAt
		}
		f.Devices = append(f.Devices, d)
	}
	// 按设备标识排序后再写：内容一样但顺序随机的文件，每次 diff 都全变，
	// 手工查看与版本管理都会变得毫无意义。
	sort.Slice(f.Devices, func(i, j int) bool { return f.Devices[i].HWID < f.Devices[j].HWID })
	if err := writeJSON(t.path, f); err != nil {
		log.Printf("[server] 设备表写入失败（%s）: %v", t.path, err)
	}
}

// shortHWID 截短设备标识用于日志。
//
// 完整标识是 32 位十六进制，打进日志会把一行撑得难读；
// 前 8 位足以在同一台服务端的日志里区分设备。
func shortHWID(hwid string) string {
	if len(hwid) <= 8 {
		return hwid
	}
	return hwid[:8]
}

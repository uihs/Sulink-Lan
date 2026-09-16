package server

import "encoding/binary"

// 服务端在虚拟网络里的地址是 10.0.0.1（IPPool.ServerVIP）。
//
// 但服务端是纯用户态进程：既没有 TUN 网卡，也没把 10.0.0.1 配到任何接口上，
// 所以这个地址没有任何内核协议栈替它应答。而 README 把 10.0.0.1 描述成
// 「服务器自身的虚拟 IP」，用户自然会拿 `ping 10.0.0.1` 当连通性自检点——
// 结果隧道明明是通的，自检却永久超时，反而把真实故障掩盖掉。
//
// 本文件在用户态直接合成 ICMP echo 应答。范围刻意收得很窄：
// 只回应「发往服务器 VIP 的 ICMPv4 echo request」，其余协议与目标一律不碰，
// 不实现任何端口服务，不引入新的可攻击面。

const (
	ipProtoICMP     = 1
	icmpEchoRequest = 8
	icmpEchoReply   = 0
)

// ipv4HeaderLen 返回 IPv4 头长度（字节）；非 IPv4 或长度非法时返回 0。
func ipv4HeaderLen(pkt []byte) int {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return 0
	}
	return ihl
}

// echoReply 判断 pkt 是否为发往 vip 的 ICMPv4 echo request；
// 是则返回对应的 echo reply（IP 地址已互换，IP 头与 ICMP 校验和已重算）。
//
// 第二个返回值为 false 时表示「不是本函数该管的包」，调用方按原逻辑处理。
func echoReply(pkt []byte, vip uint32) ([]byte, bool) {
	ihl := ipv4HeaderLen(pkt)
	if ihl == 0 {
		return nil, false
	}
	// 只认未分片的包。MF 置位或分片偏移非 0 都需要先重组才能判断，
	// 而 echo request 只有几十字节、现实中不会分片——直接忽略分片，
	// 比在服务端实现重组安全得多。注意 DF 位（0x4000）要放行：
	// 部分系统的 ping 默认置 DF，拦掉它会让「本机 ping 得通、别的机器 ping 不通」。
	if binary.BigEndian.Uint16(pkt[6:8])&0x3FFF != 0 {
		return nil, false
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl+8 || total > len(pkt) {
		return nil, false
	}
	if pkt[9] != ipProtoICMP {
		return nil, false
	}
	if binary.BigEndian.Uint32(pkt[16:20]) != vip {
		return nil, false
	}
	icmp := pkt[ihl:total]
	// type 必须为 echo request，且 code 必须为 0
	if icmp[0] != icmpEchoRequest || icmp[1] != 0 {
		return nil, false
	}

	reply := make([]byte, total)
	copy(reply, pkt[:total])
	// 源/目的地址互换：应答从服务器 VIP 发回请求方
	copy(reply[12:16], pkt[16:20])
	copy(reply[16:20], pkt[12:16])
	// ICMP 类型改为 echo reply，重算 ICMP 校验和
	reply[ihl] = icmpEchoReply
	reply[ihl+2], reply[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(reply[ihl+2:ihl+4], checksum(reply[ihl:total]))
	// IP 头地址变了，校验和必须重算
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], checksum(reply[:ihl]))
	return reply, true
}

// checksum 标准 Internet 校验和（16 位反码求和）。
func checksum(buf []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(buf); i += 2 {
		sum += uint32(buf[i])<<8 | uint32(buf[i+1])
	}
	if i < len(buf) {
		sum += uint32(buf[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

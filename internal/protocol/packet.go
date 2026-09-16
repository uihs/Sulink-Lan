package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// 数据包协议（UDP 数据通路，客户端之间 / 客户端-中继之间通用）：
//
//	┌──────┬────────┬────────┬──────────────┬────────────────────┐
//	│ flags│ srcVIP │ dstVIP │ nonce (12B)  │ ciphertext (GCM)   │
//	│ 1B   │ 4B     │ 4B     │              │                    │
//	└──────┴────────┴────────┴──────────────┴────────────────────┘
//
// ciphertext = AES-GCM(payload)，payload 为完整 IP 数据包（TUN 三层转发）。
// flags 高 4 位为包类型，低 4 位保留：
//	0x10 数据包（封装的 IP 包）
//	0x20 打洞探测包（payload 为空）
//	0x30 打洞探测回复（payload 为空）

const (
	FlagData      = 0x10 // 封装的 IP 数据包（TUN 三层转发）
	FlagProbe     = 0x20 // 打洞探测包
	FlagReply     = 0x30 // 打洞探测回复
	FlagProxyData = 0x40 // 已废弃：公网端口映射的 TCP 流数据（保留编号，两侧实现均已删除）

	HeaderLen = 1 + 4 + 4 + 12
	NonceLen  = 12

	// MaxPayload 单个 IP 包上限，配合 TUN MTU=1420 使用。
	MaxPayload = 1500
	// MaxPacket UDP 包上限 = 头 + GCM 密文最大长度。
	MaxPacket = HeaderLen + MaxPayload + 16
)

// Packet 解析后的数据包。
type Packet struct {
	Flags  uint8
	Source uint32 // 源虚拟 IP
	Dest   uint32 // 目标虚拟 IP
	Data   []byte // 解密后的载荷（IP 包）
}

// Crypto 负责数据包的 AES-GCM 加解密与信令认证。
type Crypto struct {
	aead    cipher.AEAD
	authKey []byte
}

// NewCryptoWithKeys 用显式指定的数据面与认证密钥创建加解密器。
// 数据面用服务端下发的网络密钥，认证用设备密钥派生——
// 两者分离，设备密钥泄露不影响数据面，网络密钥泄露不影响认证。
func NewCryptoWithKeys(dataKey, authKey []byte) (*Crypto, error) {
	if len(dataKey) != 32 {
		return nil, errors.New("数据面密钥长度错误（应为 32 字节）")
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Crypto{aead: aead, authKey: authKey}, nil
}

// AuthTagFor 用给定的认证密钥计算认证标签：HMAC-SHA256(authKey, nonce)。
// 供不经过 Crypto 的临时密钥使用（如自动注册流程按 HWID 派生的认证密钥）。
func AuthTagFor(authKey, nonce []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(nonce)
	return mac.Sum(nil)
}

// AuthTag 计算认证标签：HMAC-SHA256(authKey, nonce)。
// 用于信令握手：服务器下发随机 nonce，客户端在 Hello 中携带标签证明持有密钥。
func (c *Crypto) AuthTag(nonce []byte) []byte {
	return AuthTagFor(c.authKey, nonce)
}

// VerifyAuth 常量时间比较认证标签。
func (c *Crypto) VerifyAuth(nonce, tag []byte) bool {
	return hmac.Equal(c.AuthTag(nonce), tag)
}

// Encrypt 将 IP 包封装为密文数据包。flag 为 FlagData/FlagProbe/FlagReply。
func (c *Crypto) Encrypt(flag uint8, src, dst uint32, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, errors.New("payload too large")
	}
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, HeaderLen+len(payload)+c.aead.Overhead())
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], src)
	binary.BigEndian.PutUint32(out[5:9], dst)
	copy(out[9:21], nonce)
	c.aead.Seal(out[HeaderLen:HeaderLen], nonce, payload, out[:HeaderLen])
	return out, nil
}

// Decrypt 解析并解密数据包。
func (c *Crypto) Decrypt(buf []byte) (*Packet, error) {
	if len(buf) < HeaderLen {
		return nil, errors.New("packet too short")
	}
	flag := buf[0]
	src := binary.BigEndian.Uint32(buf[1:5])
	dst := binary.BigEndian.Uint32(buf[5:9])
	nonce := buf[9:21]
	ct := buf[HeaderLen:]
	pt, err := c.aead.Open(nil, nonce, ct, buf[:HeaderLen])
	if err != nil {
		return nil, err
	}
	return &Packet{Flags: flag, Source: src, Dest: dst, Data: pt}, nil
}

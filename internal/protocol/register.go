// 自动注册的设备凭证与注册响应加解密。
//
// 凭证模型：每台设备持有「设备 ID + 设备密钥」两个长期值。
//   - 设备 ID：随机 16 字节，base32 编码（无填充），认证时明文上报，
//     服务端据此查表——它只是索引，泄露无碍。
//   - 设备密钥：随机 32 字节，hex 编码（64 字符），服务端与客户端各存一份，
//     认证时用于 HMAC-SHA256 应答挑战。泄露等于设备身份被冒充。
//
// 注册响应（服务端 -> 客户端）用设备标识（HWID）派生的密钥做 AES-GCM 加密：
// 客户端打开软件时凭本机 HWID 自动向服务端注册，服务端签发凭证后
// 用 HWID 派生的密钥加密回传——只有持有该硬件标识的客户端能解开
// 凭证包，拿到自己的设备密钥。HWID 本身只是机器标识，不是秘密，
// 因此这套「自动注册」的信任模型是：能算得出服务端地址即可入网，
// 设备身份由 HWID 绑定（详见 server.handleRegister 的说明）。
package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// 注册 / 凭证字段的域分隔串，防止跨用途派生。
const (
	registerBlobInfo = "sulink-lan/v1/register-blob" // 注册响应加密密钥
	registerAuthInfo = "sulink-lan/v1/register-auth" // 注册请求的临时认证密钥
	deviceAuthInfo   = "sulink-lan/v1/device-auth"   // 设备凭证的认证密钥
)

// Credential 设备凭证包（注册响应的载荷）。
type Credential struct {
	DeviceID   string `json:"deviceId"`
	DeviceKey  string `json:"deviceKey"`  // hex，32 字节
	NetworkKey string `json:"networkKey"` // hex，32 字节；数据面共享密钥（自动注册签发）
}

// GenerateDeviceID 生成设备 ID：16 字节随机 -> base32 无填充（26 字符）。
func GenerateDeviceID() (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// GenerateKey 生成 32 字节随机密钥，hex 编码返回。
func GenerateKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ParseKey 解析 hex 编码的 32 字节密钥。
func ParseKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("设备密钥长度错误（应为 32 字节）")
	}
	return key, nil
}

// RegisterAuthKey 注册请求的临时认证密钥：HMAC-SHA256(设备标识)。
// 客户端用它应答服务端挑战，证明「我就是这台设备」；服务端据此
// 决定是否为该 HWID 签发 / 复用设备凭证。
func RegisterAuthKey(hwid string) []byte {
	mac := hmac.New(sha256.New, []byte(hwid))
	mac.Write([]byte(registerAuthInfo))
	return mac.Sum(nil)
}

// DeviceAuthKey 设备凭证的认证密钥：HMAC-SHA256(设备密钥)。
// 与数据面密钥分离——设备密钥只用于信令认证，数据面用网络密钥。
func DeviceAuthKey(deviceKey []byte) []byte {
	mac := hmac.New(sha256.New, deviceKey)
	mac.Write([]byte(deviceAuthInfo))
	return mac.Sum(nil)
}

// VerifyRegisterAuth 常量时间验证注册请求的认证标签（HMAC-SHA256(HWID, nonce)）。
// HWID 作为设备持有的临时凭证应答挑战，证明「确实来自这台设备」。
func VerifyRegisterAuth(hwid string, nonce, tag []byte) bool {
	if len(tag) == 0 {
		return false
	}
	authKey := RegisterAuthKey(hwid)
	mac := hmac.New(sha256.New, authKey)
	mac.Write(nonce)
	return hmac.Equal(mac.Sum(nil), tag)
}

// VerifyDeviceAuth 常量时间验证设备凭证的认证标签
// （HMAC-SHA256(DeviceAuthKey(deviceKey), nonce)）。deviceKey 为 hex 编码。
func VerifyDeviceAuth(deviceKeyHex string, nonce, tag []byte) bool {
	if len(tag) == 0 {
		return false
	}
	key, err := ParseKey(deviceKeyHex)
	if err != nil {
		return false
	}
	authKey := DeviceAuthKey(key)
	mac := hmac.New(sha256.New, authKey)
	mac.Write(nonce)
	return hmac.Equal(mac.Sum(nil), tag)
}

// EncryptCredential 用设备标识派生的密钥加密凭证包。
// 返回 nonce(12B) || AES-GCM 密文。
func EncryptCredential(hwid string, cred *Credential) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(hwid))
	mac.Write([]byte(registerBlobInfo))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, len(nonce), len(nonce)+len(payload)+aead.Overhead())
	copy(out, nonce)
	return aead.Seal(out, nonce, payload, nil), nil
}

// DecryptCredential 用设备标识解密服务端下发的凭证包。
func DecryptCredential(hwid string, blob []byte) (*Credential, error) {
	mac := hmac.New(sha256.New, []byte(hwid))
	mac.Write([]byte(registerBlobInfo))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("注册响应太短")
	}
	nonce := blob[:aead.NonceSize()]
	payload, err := aead.Open(nil, nonce, blob[aead.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("注册响应解密失败（设备标识与服务端不匹配？）")
	}
	var cred Credential
	if err := json.Unmarshal(payload, &cred); err != nil {
		return nil, errors.New("注册响应格式错误")
	}
	if cred.DeviceID == "" || cred.DeviceKey == "" || cred.NetworkKey == "" {
		return nil, errors.New("注册响应缺少字段")
	}
	return &cred, nil
}

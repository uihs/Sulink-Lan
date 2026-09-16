package protocol

import (
	"bytes"
	"testing"
)

// TestCredentialRoundTrip 注册响应加密/解密往返必须还原凭证。
func TestCredentialRoundTrip(t *testing.T) {
	cred := &Credential{
		DeviceID:   "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		DeviceKey:  "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		NetworkKey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
	hwid := "test-hwid-roundtrip"
	blob, err := EncryptCredential(hwid, cred)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptCredential(hwid, blob)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *cred {
		t.Fatalf("往返不一致:\n got %+v\nwant %+v", *got, *cred)
	}
}

// TestCredentialWrongHWID 用错误的设备标识解密必须失败（防伪造/防窃听套用）。
func TestCredentialWrongHWID(t *testing.T) {
	cred := &Credential{DeviceID: "X", DeviceKey: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", NetworkKey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}
	blob, err := EncryptCredential("hwid-right", cred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptCredential("hwid-wrong", blob); err == nil {
		t.Fatal("错误设备标识不应解密成功")
	}
	// 截断的 blob 也必须失败
	if _, err := DecryptCredential("hwid-right", blob[:10]); err == nil {
		t.Fatal("截断的注册响应不应解密成功")
	}
}

// TestVerifyRegisterAuth 注册请求的挑战应答必须区分持有/未持有设备标识。
func TestVerifyRegisterAuth(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	tag := AuthTagFor(RegisterAuthKey("hwid-123"), nonce)
	if !VerifyRegisterAuth("hwid-123", nonce, tag) {
		t.Fatal("持有设备标识的应答应通过验证")
	}
	if VerifyRegisterAuth("hwid-124", nonce, tag) {
		t.Fatal("不同设备标识的应答不应通过验证")
	}
	if VerifyRegisterAuth("hwid-123", nonce, nil) {
		t.Fatal("空标签不应通过验证")
	}
}

// TestVerifyDeviceAuth 设备凭证的挑战应答必须区分持有/未持有密钥。
func TestVerifyDeviceAuth(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("0123456789abcdef0123456789abcdef")
	keyBytes, _ := ParseKey(key)
	tag := AuthTagFor(DeviceAuthKey(keyBytes), nonce)
	if !VerifyDeviceAuth(key, nonce, tag) {
		t.Fatal("持有设备密钥的应答应通过验证")
	}
	if VerifyDeviceAuth(key, nonce, append(tag, 0)) {
		t.Fatal("篡改的标签不应通过验证")
	}
}

// TestGenerateIDAndKey 设备 ID / 密钥格式自检。
func TestGenerateIDAndKey(t *testing.T) {
	id, err := GenerateDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 26 {
		t.Fatalf("设备 ID 应为 26 字符 base32，实际 %d", len(id))
	}
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ParseKey(key)
	if err != nil || len(kb) != 32 {
		t.Fatalf("设备密钥应为 32 字节，实际 %d (err=%v)", len(kb), err)
	}
	// 两次生成不应相同（随机性）
	id2, _ := GenerateDeviceID()
	if id == id2 {
		t.Fatal("两次生成的设备 ID 不应相同")
	}
}

// TestNewCryptoWithKeys 显式密钥构造的加解密必须可用。
func TestNewCryptoWithKeys(t *testing.T) {
	dataKey := bytes.Repeat([]byte{1}, 32)
	authKey := bytes.Repeat([]byte{2}, 32)
	c, err := NewCryptoWithKeys(dataKey, authKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("nonce0123456789")
	tag := c.AuthTag(nonce)
	if !c.VerifyAuth(nonce, tag) {
		t.Fatal("显式密钥构造的认证应自洽")
	}
	if _, err := NewCryptoWithKeys([]byte("short"), authKey); err == nil {
		t.Fatal("短数据密钥应被拒绝")
	}
}

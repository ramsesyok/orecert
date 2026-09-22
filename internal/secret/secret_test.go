package secret

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordSources(t *testing.T) {
	file := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(file, []byte("file secret\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ source, want string }{{"direct", "direct"}, {"file:" + file, "file secret"}, {"prompt:", "typed"}} {
		got, err := resolve(tt.source, func() ([]byte, error) { return []byte("typed"), nil })
		if err != nil || string(got) != tt.want {
			t.Fatalf("%s: %q %v", tt.source, got, err)
		}
	}
	for _, source := range []string{"", "file:", "file:missing"} {
		if _, err := resolve(source, nil); err == nil {
			t.Fatalf("拒否されませんでした: %s", source)
		}
	}
	count := 0
	if _, err := resolve("prompt:", func() ([]byte, error) { count++; return nil, nil }); err == nil || count != 3 {
		t.Fatal("空パスワードの再試行制限")
	}
	if _, err := resolve("prompt:", func() ([]byte, error) { return nil, errors.New("interrupted") }); err == nil {
		t.Fatal("入力エラー")
	}
}

func TestMalformedKeyInputs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	for _, data := range [][]byte{[]byte("bad"), pem.EncodeToMemory(&pem.Block{Type: "WRONG", Bytes: []byte("bad")}), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("bad")}), bytes.Repeat([]byte("x"), 1024*1024+1)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadKey(path, "test"); err == nil {
			t.Fatal("破損した秘密鍵を許可しました")
		}
	}
	if _, err := readLimited(dir); err == nil {
		t.Fatal("ディレクトリ")
	}
	if _, err := Encode(struct{}{}, true, []byte("test")); err == nil {
		t.Fatal("未対応鍵")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encode(key, true, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.CreateTemp(dir, "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	original := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = original })
	if _, err := ReadKey(path, ""); err == nil {
		t.Fatal("非対話環境での入力待ち")
	}
	block, _ := pem.Decode(encrypted)
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	if _, err := asn1.Unmarshal(block.Bytes, &info); err != nil {
		t.Fatal(err)
	}
	// CBCブロック境界の破損をパニックではなくエラーにします。
	info.Data = info.Data[:len(info.Data)-1]
	bad, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEncrypted(bad); err == nil {
		t.Fatal("CBC長の検証")
	}
	info.Algorithm.Parameters.FullBytes = []byte{0x30, 0}
	bad, err = asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEncrypted(bad); err == nil {
		t.Fatal("PBES2パラメータの検証")
	}
}

func TestEncryptedKeyRoundTrip(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encode(key, true, []byte("test secret"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatal(block.Type)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadKey(path, "test secret")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.(ed25519.PrivateKey), key) {
		t.Fatal("鍵の不一致")
	}
	if _, err := ReadKey(path, "wrong"); err == nil {
		t.Fatal("誤ったパスワードを拒否しませんでした")
	}
	if _, err := Encode(key, true, nil); err == nil {
		t.Fatal("空パスワードを拒否しませんでした")
	}
}

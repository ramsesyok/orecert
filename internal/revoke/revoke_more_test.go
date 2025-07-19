package revoke

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestRevoke_Multiple は CRL が 2 件になることを確認します。
func TestRevoke_Multiple(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	issueCert(t, dir, "a", cfg)
	issueCert(t, dir, "b", cfg)
	os.Chdir(dir)
	if err := Revoke(cfg, Profile{CN: "a"}); err != nil {
		t.Fatalf("1 回目の revoke 失敗: %v", err)
	}
	if err := Revoke(cfg, Profile{CN: "b"}); err != nil {
		t.Fatalf("2 回目の revoke 失敗: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join("certs", "ca", "crl.pem"))
	blk, _ := pem.Decode(data)
	rl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatalf("CRL 解析失敗: %v", err)
	}
	if len(rl.RevokedCertificateEntries) != 2 {
		t.Fatalf("2 件であるべき: %d", len(rl.RevokedCertificateEntries))
	}
	if rl.Number == nil || rl.Number.Int64() != 2 {
		t.Fatalf("番号 2 が期待されるが: %v", rl.Number)
	}
}

// TestRevoke_CRLMissing は CRL が無い場合にエラーとなることを確認します。
func TestRevoke_CRLMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	issueCert(t, dir, "x", cfg)
	os.Chdir(dir)
	os.Remove(filepath.Join("certs", "ca", "crl.pem"))
	if err := Revoke(cfg, Profile{CN: "x"}); err == nil {
		t.Fatal("エラーが必要")
	}
}

// CA 証明書が壊れている場合のエラーを確認します。
func TestRevoke_BrokenCACert(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	issueCert(t, dir, "y", cfg)
	os.Chdir(dir)
	os.WriteFile(cfg.CA.Cert, []byte("BAD"), 0644)
	if err := Revoke(cfg, Profile{CN: "y"}); err == nil {
		t.Fatal("エラーが必要")
	}
}

package bundle

import (
	"bytes"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"testing"
)

func TestBundleRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	generateCert(t, dir, "host")
	if err := os.Rename("certs/host", "outside"); err != nil {
		t.Fatal(err)
	}
	if err := Bundle(Config{PKCS12Password: "secret"}, "../outside", "all"); err == nil {
		t.Fatal("certs外への出力を拒否しませんでした")
	}
}

func TestBundleRejectsMismatchedKeyAndIssuer(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	generateCert(t, dir, "host")
	key, err := os.ReadFile("certs/host/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := os.ReadFile("certs/ca/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("certs/host/key.pem", caKey, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{PKCS12Password: "secret"}
	if err := Bundle(cfg, "host", "all"); err == nil {
		t.Fatal("不一致の鍵")
	}
	if err := os.WriteFile("certs/host/key.pem", key, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.CA.Cert = "certs/host/cert.pem"
	if err := Bundle(cfg, "host", "all"); err == nil {
		t.Fatal("CA領域との衝突")
	}
	if _, err := os.Stat("certs/host/bundle.p12"); !os.IsNotExist(err) {
		t.Fatal("失敗時にバンドルを生成")
	}
}

func TestModernAndLegacyPasswords(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	generateCert(t, dir, "host")
	for _, legacy := range []bool{false, true} {
		cfg := Config{PKCS12Password: "test secret", Overwrite: true, Legacy: legacy}
		if err := Bundle(cfg, "host", "pkcs"); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile("certs/host/bundle.p12")
		if err != nil {
			t.Fatal(err)
		}
		key, cert, chain, err := pkcs12.DecodeChain(data, "test secret")
		if err != nil || key == nil || cert == nil || len(chain) != 1 {
			t.Fatalf("P12復号: %v", err)
		}
		if _, _, _, err := pkcs12.DecodeChain(data, "wrong"); err == nil {
			t.Fatal("誤パスワード")
		}
		// PBES2のOIDで、既定出力が旧方式に戻っていないことを確認します。
		if modern := bytes.Contains(data, []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d}); modern == legacy {
			t.Fatal("P12暗号方式")
		}
	}
}

func TestBundleRejectsEmptyPassword(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	generateCert(t, dir, "host")
	if err := Bundle(Config{}, "host", "pkcs"); err == nil {
		t.Fatal("空パスワードを拒否しませんでした")
	}
}

func TestBundlePreservesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	generateCert(t, dir, "host")
	cfg := Config{PKCS12Password: "secret"}
	if err := Bundle(cfg, "host", "all"); err != nil {
		t.Fatal(err)
	}
	if err := Bundle(cfg, "host", "all"); err == nil {
		t.Fatal("既存バンドルを上書きしました")
	}
}

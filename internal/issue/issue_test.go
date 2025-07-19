package issue_test

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"orecert/internal/ca"
	"orecert/internal/issue"
)

func createCA(t *testing.T, dir string) issue.Config {
	t.Helper()
	cfg := issue.Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	if err := ca.InitCA(ca.Config{CA: cfg.CA}); err != nil {
		t.Fatalf("init ca: %v", err)
	}
	return cfg
}

func TestIssue_GeneratesFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	cfg.Overwrite = false

	prof := issue.Profile{CN: "localhost", SAN: []string{"DNS:localhost"}}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(cfg, prof, "server"); err != nil {
		t.Fatalf("issue: %v", err)
	}

	paths := []string{
		filepath.Join("certs", "localhost", "key.pem"),
		filepath.Join("certs", "localhost", "csr.pem"),
		filepath.Join("certs", "localhost", "cert.pem"),
		filepath.Join("certs", "localhost", "fullchain.pem"),
		filepath.Join("certs", "localhost", "meta.json"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s not created", p)
		}
	}
}

func TestIssue_OverwriteCheck(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)

	prof := issue.Profile{CN: "dup"}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	// first run
	if err := issue.Issue(cfg, prof, "client"); err != nil {
		t.Fatal(err)
	}
	// second run without overwrite should fail
	if err := issue.Issue(cfg, prof, "client"); err != issue.ErrExists {
		t.Fatalf("expected ErrExists, got %v", err)
	}
}

func TestIssue_InvalidCN(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	prof := issue.Profile{CN: "../bad"}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(cfg, prof, "server"); err != issue.ErrInvalidCN {
		t.Fatalf("expected ErrInvalidCN, got %v", err)
	}
}

func TestIssue_InvalidType(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	prof := issue.Profile{CN: "x"}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(cfg, prof, "bad"); err != issue.ErrInvalidType {
		t.Fatalf("expected ErrInvalidType, got %v", err)
	}
}

func TestFingerprintFormat(t *testing.T) {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("dummy")}
	got := issue.Fingerprint(pem.EncodeToMemory(block))
	if len(got) == 0 {
		t.Fatal("fingerprint empty")
	}
}

func TestParseHelpers(t *testing.T) {
	dns := issue.ParseDNS([]string{"DNS:a"})
	if len(dns) != 1 || dns[0] != "a" {
		t.Fatalf("parse dns failed")
	}
	ips := issue.ParseIP([]string{"IP:127.0.0.1"})
	if len(ips) != 1 || ips[0].String() != "127.0.0.1" {
		t.Fatalf("parse ip failed")
	}
	uris := issue.ParseURI([]string{"URI:https://example.com"})
	if len(uris) != 1 || uris[0].Host != "example.com" {
		t.Fatalf("parse uri failed")
	}
	emails := issue.ParseEmail([]string{"EMAIL:a@example.com"})
	if len(emails) != 1 || emails[0] != "a@example.com" {
		t.Fatalf("parse email failed")
	}
}

func TestAlgoString(t *testing.T) {
	if issue.AlgoString("rsa", 2048) != "RSA-2048" {
		t.Fatal("algostring rsa")
	}
	if issue.AlgoString("ecdsa", 0) != "ECDSA-P256" {
		t.Fatal("algostring ecdsa")
	}
	if issue.AlgoString("ed25519", 0) != "Ed25519" {
		t.Fatal("algostring ed25519")
	}
}

func TestHelpers(t *testing.T) {
	algos := []string{"rsa", "ecdsa", "ed25519"}
	for _, a := range algos {
		priv, pub, err := issue.GenerateKey(a, 2048)
		if err != nil || priv == nil || pub == nil {
			t.Fatalf("generate %s", a)
		}
		path := filepath.Join(t.TempDir(), a+".pem")
		if err := issue.WriteKey(path, priv); err != nil {
			t.Fatal(err)
		}
		if _, err := issue.ReadKey(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateKeyAlgorithms(t *testing.T) {
	algos := []string{"rsa", "ecdsa", "ed25519"}
	for _, a := range algos {
		priv, pub, err := issue.GenerateKey(a, 2048)
		if err != nil || priv == nil || pub == nil {
			t.Fatalf("key gen %s", a)
		}
	}
}

func TestReadCert(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	cert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil || cert == nil {
		t.Fatal("read cert fail")
	}
}

func TestErrorBranches(t *testing.T) {
	if _, _, err := issue.GenerateKey("bad", 0); err == nil {
		t.Fatal("expected error")
	}
	if err := issue.WriteKey(filepath.Join(t.TempDir(), "k"), struct{}{}); err == nil {
		t.Fatal("expected error")
	}
	badKey := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(badKey, []byte("BAD"), 0644)
	if _, err := issue.ReadKey(badKey); err == nil {
		t.Fatal("expected read error")
	}
	if _, err := issue.ReadCert(badKey); err == nil {
		t.Fatal("expected read cert error")
	}
}

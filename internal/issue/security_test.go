package issue_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"gopkg.in/yaml.v3"
	"orecert/internal/issue"
	"os"
	"strings"
	"testing"
)

func TestProfileRSAKeyLength(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := createCA(t, dir)
	var p issue.Profile
	if err := yaml.Unmarshal([]byte("cn: host\nrsa_bits: 3072\n"), &p); err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(cfg, p, "server"); err != nil {
		t.Fatal(err)
	}
	cert, err := issue.ReadCert("certs/host/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if cert.PublicKey.(*rsa.PublicKey).N.BitLen() != 3072 {
		t.Fatal("指定した鍵長が反映されていません")
	}
}

func TestInvalidProfileDoesNotWrite(t *testing.T) {
	t.Chdir(t.TempDir())
	invalid := []issue.Profile{{CN: "host", Days: -1}, {CN: "host", KeyPass: "secret"}, {CN: "host", RSABits: 1024}}
	for _, san := range []string{"DNS:", "host", "IP:999.0.0.1", "URI:%", "URI:relative", "EMAIL:bad", "EMAIL:@host", "UNKNOWN:host", "DNS:a..b", "DNS:-host", "DNS:a_b", "DNS:" + strings.Repeat("x", 254)} {
		invalid = append(invalid, issue.Profile{CN: "host", SAN: []string{san}})
	}
	for _, profile := range invalid {
		if err := issue.Issue(issue.Config{}, profile, "server"); err == nil {
			t.Fatalf("不正なプロファイルを許可: %+v", profile)
		}
	}
	if _, err := os.Stat("certs/host/key.pem"); !os.IsNotExist(err) {
		t.Fatal("不正入力で鍵を保存")
	}
}

func TestAllSANAndCAPeriod(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := createCA(t, dir)
	profile := issue.Profile{CN: "host", Algo: "ecdsa", Days: 1000, SAN: []string{"DNS:*.example.test", "IP:::1", "URI:spiffe://example.test/service", "EMAIL:test@example.test"}}
	if err := issue.Issue(cfg, profile, "both"); err != nil {
		t.Fatal(err)
	}
	cert, err := issue.ReadCert("certs/host/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if cert.NotAfter.After(caCert.NotAfter) || len(cert.URIs) != 1 || len(cert.EmailAddresses) != 1 || len(cert.IPAddresses) != 1 {
		t.Fatal("証明書属性が不正")
	}
	csrData, err := os.ReadFile("certs/host/csr.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrData)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		t.Fatal("CSR不整合")
	}
}

func TestCAPathConflictAndBrokenCA(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := createCA(t, dir)
	cfg.CA.Key = "certs/host/key.pem"
	if err := issue.Issue(cfg, issue.Profile{CN: "host"}, "server"); err == nil {
		t.Fatal("カスタムCAパスの衝突")
	}
	cfg = createCAConfig(dir)
	if err := os.WriteFile(cfg.CA.Key, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(cfg, issue.Profile{CN: "host", Algo: "ecdsa"}, "server"); err == nil {
		t.Fatal("破損CA鍵")
	}
}

func createCAConfig(dir string) issue.Config {
	cfg := issue.Config{}
	cfg.CA.Key = dir + "/certs/ca/key.pem"
	cfg.CA.Cert = dir + "/certs/ca/cert.pem"
	return cfg
}

func TestReservedCNPreservesCA(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := createCA(t, dir)
	cfg.Overwrite = true
	before, err := os.ReadFile(cfg.CA.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(cfg, issue.Profile{CN: "ca"}, "server"); err == nil {
		t.Error("CA領域への発行を拒否しませんでした")
	}
	after, err := os.ReadFile(cfg.CA.Key)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("CA秘密鍵が変更されました")
	}
}

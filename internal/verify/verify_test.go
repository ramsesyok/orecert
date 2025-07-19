package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"orecert/internal/ca"
	"orecert/internal/issue"
)

func createCA(t *testing.T, dir string) Config {
	t.Helper()
	c := Config{}
	c.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	caCfg := ca.Config{}
	caCfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	caCfg.CA.Cert = c.CA.Cert
	if err := ca.InitCA(caCfg); err != nil {
		t.Fatalf("init ca: %v", err)
	}
	return c
}

func issueCert(t *testing.T, dir, cn string, notAfter time.Time, caDir string) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyPath := filepath.Join(dir, "certs", cn, "key.pem")
	os.MkdirAll(filepath.Dir(keyPath), 0755)
	os.WriteFile(keyPath, keyPEM, 0600)

	caCertBytes, _ := os.ReadFile(filepath.Join(caDir, "certs", "ca", "cert.pem"))
	caBlock, _ := pem.Decode(caCertBytes)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	caKeyBytes, _ := os.ReadFile(filepath.Join(caDir, "certs", "ca", "key.pem"))
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	caKey, _ := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)

	tmpl := &x509.Certificate{SerialNumber: bigInt(t), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath := filepath.Join(dir, "certs", cn, "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}

func bigInt(t *testing.T) *big.Int {
	b, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func TestVerify_OK(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	issueCert(t, dir, "ok", time.Now().AddDate(0, 0, 1), dir)
	prof := Profile{CN: "ok"}
	if err := Verify(cfg, prof); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	os.Chdir(dir)
	issueCert(t, dir, "exp", time.Now().AddDate(0, 0, -1), dir)
	prof := Profile{CN: "exp"}
	if err := Verify(cfg, prof); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerify_InvalidCN(t *testing.T) {
	if err := Verify(Config{}, Profile{CN: "../bad"}); err != issue.ErrInvalidCN {
		t.Fatalf("expected invalid cn")
	}
}

func TestVerify_BadCA(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	os.Chdir(dir)
	issueCert(t, dir, "badca", time.Now().AddDate(0, 0, 1), dir)
	cfg.CA.Cert = filepath.Join(dir, "none.pem")
	if err := Verify(cfg, Profile{CN: "badca"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestVerify_ChainFail(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	other := filepath.Join(dir, "other")
	os.MkdirAll(other, 0755)
	createCA(t, other)
	os.Chdir(dir)
	issueCert(t, dir, "cfail", time.Now().AddDate(0, 0, 1), other)
	if err := Verify(cfg, Profile{CN: "cfail"}); err != ErrVerify {
		t.Fatalf("expected ErrVerify, got %v", err)
	}
}

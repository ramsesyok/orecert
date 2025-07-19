package revoke

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
)

func createCA(t *testing.T, dir string) Config {
	t.Helper()
	cfg := Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	if err := ca.InitCA(ca.Config{CA: cfg.CA}); err != nil {
		t.Fatalf("init ca: %v", err)
	}
	return cfg
}

func issueCert(t *testing.T, dir, cn string, cfg Config) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyPath := filepath.Join(dir, "certs", cn, "key.pem")
	os.MkdirAll(filepath.Dir(keyPath), 0755)
	os.WriteFile(keyPath, keyPEM, 0600)

	caCertBytes, _ := os.ReadFile(cfg.CA.Cert)
	caBlock, _ := pem.Decode(caCertBytes)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	caKeyBytes, _ := os.ReadFile(cfg.CA.Key)
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	caKey, _ := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)

	tmpl := &x509.Certificate{SerialNumber: bigInt(t), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 0, 1), KeyUsage: x509.KeyUsageDigitalSignature}
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

func TestRevoke_OK(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	issueCert(t, dir, "host", cfg)
	os.Chdir(dir)
	prof := Profile{CN: "host"}
	if err := Revoke(cfg, prof); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join("certs", "ca", "crl.pem"))
	blk, _ := pem.Decode(data)
	rl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil || len(rl.RevokedCertificateEntries) != 1 {
		t.Fatalf("crl not updated")
	}
}

func TestRevoke_InvalidCN(t *testing.T) {
	if err := Revoke(Config{}, Profile{CN: "../bad"}); err == nil {
		t.Fatalf("expected invalid cn")
	}
}

func TestRevoke_BadCA(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	os.Chdir(dir)
	cfg.CA.Cert = filepath.Join(dir, "none.pem")
	if err := Revoke(cfg, Profile{CN: "none"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRevoke_BadKey(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	os.Chdir(dir)
	cfg.CA.Key = filepath.Join(dir, "none.pem")
	if err := Revoke(cfg, Profile{CN: "none"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRevoke_NoCert(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	os.Chdir(dir)
	if err := Revoke(cfg, Profile{CN: "none"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRevoke_InvalidCRL(t *testing.T) {
	dir := t.TempDir()
	cfg := createCA(t, dir)
	os.Chdir(dir)
	os.WriteFile(filepath.Join("certs", "ca", "crl.pem"), []byte("BAD"), 0644)
	issueCert(t, dir, "h", cfg)
	if err := Revoke(cfg, Profile{CN: "h"}); err == nil {
		t.Fatalf("expected error")
	}
}

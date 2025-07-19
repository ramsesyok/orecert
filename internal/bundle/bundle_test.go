package bundle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

func generateCert(t *testing.T, dir, cn string) {
	t.Helper()
	// create CA first
	cfg := ca.Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	if err := ca.InitCA(cfg); err != nil {
		t.Fatalf("init ca: %v", err)
	}

	// load CA key and cert
	caKeyBytes, _ := os.ReadFile(cfg.CA.Key)
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse ca key: %v", err)
	}
	caCertBytes, _ := os.ReadFile(cfg.CA.Cert)
	caCertBlock, _ := pem.Decode(caCertBytes)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}

	// generate leaf key
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	leafKeyPath := filepath.Join(dir, "certs", cn, "key.pem")
	os.MkdirAll(filepath.Dir(leafKeyPath), 0755)
	os.WriteFile(leafKeyPath, leafKeyPEM, 0600)

	// create cert
	tmpl := &x509.Certificate{
		SerialNumber:          bigInt(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certPath := filepath.Join(dir, "certs", cn, "cert.pem")
	os.WriteFile(certPath, certPEM, 0644)
}

func bigInt(t *testing.T) *big.Int {
	b, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func TestBundle_All(t *testing.T) {
	dir := t.TempDir()
	generateCert(t, dir, "localhost")

	cfg := Config{PKCS12Password: "pass"}
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	os.Chdir(dir)
	err := Bundle(cfg, "localhost", "all")
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join("certs", "localhost", "bundle.p12")); err != nil {
		t.Errorf("p12 not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join("certs", "localhost", "bundle.jks")); err != nil {
		t.Errorf("jks not created: %v", err)
	}
}

func TestBundle_Unsupported(t *testing.T) {
	dir := t.TempDir()
	generateCert(t, dir, "host")

	cfg := Config{PKCS12Password: "pass"}
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	os.Chdir(dir)
	if err := Bundle(cfg, "host", "xxx"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBundle_PKCS(t *testing.T) {
	dir := t.TempDir()
	generateCert(t, dir, "only")

	cfg := Config{PKCS12Password: "pass"}
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	os.Chdir(dir)
	err := Bundle(cfg, "only", "pkcs")
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join("certs", "only", "bundle.p12")); err != nil {
		t.Errorf("p12 missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join("certs", "only", "bundle.jks")); err == nil {
		t.Errorf("jks should not exist")
	}
}

func TestReadKey_Error(t *testing.T) {
	if err := Bundle(Config{}, "none", "pkcs"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBundle_ECDSA(t *testing.T) {
	dir := t.TempDir()
	// create CA and cert with ECDSA key
	cfg := ca.Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	if err := ca.InitCA(cfg); err != nil {
		t.Fatalf("init ca: %v", err)
	}

	caKeyBytes, _ := os.ReadFile(cfg.CA.Key)
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	caKey, _ := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	caCertBytes, _ := os.ReadFile(cfg.CA.Cert)
	caCertBlock, _ := pem.Decode(caCertBytes)
	caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	keyPath := filepath.Join(dir, "certs", "ecdsa", "key.pem")
	os.MkdirAll(filepath.Dir(keyPath), 0755)
	os.WriteFile(keyPath, keyPEM, 0600)
	tmpl := &x509.Certificate{SerialNumber: bigInt(t), Subject: pkix.Name{CommonName: "ecdsa"}, NotAfter: time.Now().AddDate(0, 0, 1), NotBefore: time.Now(), KeyUsage: x509.KeyUsageDigitalSignature}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	certPath := filepath.Join(dir, "certs", "ecdsa", "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)

	cfg2 := Config{PKCS12Password: "pass"}
	cfg2.CA.Cert = cfg.CA.Cert
	os.Chdir(dir)
	if err := Bundle(cfg2, "ecdsa", "jks"); err != nil {
		t.Fatalf("bundle ecdsa: %v", err)
	}
	if _, err := os.Stat(filepath.Join("certs", "ecdsa", "bundle.jks")); err != nil {
		t.Fatalf("jks missing: %v", err)
	}
}

func TestBundle_PKCS8_BadCert(t *testing.T) {
	dir := t.TempDir()
	cfg := ca.Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	ca.InitCA(cfg)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(make([]byte, 32)))
	os.MkdirAll(filepath.Join(dir, "certs", "bad"), 0755)
	os.WriteFile(filepath.Join(dir, "certs", "bad", "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	os.WriteFile(filepath.Join(dir, "certs", "bad", "cert.pem"), []byte("bad"), 0644)
	cfg2 := Config{PKCS12Password: "pass"}
	cfg2.CA.Cert = cfg.CA.Cert
	os.Chdir(dir)
	if err := Bundle(cfg2, "bad", "pkcs"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBundle_MissingCA(t *testing.T) {
	dir := t.TempDir()
	generateCert(t, dir, "miss")
	cfg := Config{PKCS12Password: "pass"}
	cfg.CA.Cert = filepath.Join(dir, "none.pem")
	os.Chdir(dir)
	if err := Bundle(cfg, "miss", "pkcs"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestWritePKCS12_Error(t *testing.T) {
	err := writePKCS12(t.TempDir(), struct{}{}, &x509.Certificate{}, &x509.Certificate{}, "p")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestWriteJKS_Error(t *testing.T) {
	err := writeJKS("/no/such/dir", struct{}{}, &x509.Certificate{}, &x509.Certificate{}, "p")
	if err == nil {
		t.Fatalf("expected error")
	}
}

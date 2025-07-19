package ca_test

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"orecert/internal/ca"
)

func TestInitCA_GeneratesFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := ca.Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")

	if err := ca.InitCA(cfg); err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	if _, err := os.Stat(cfg.CA.Key); err != nil {
		t.Errorf("key not created: %v", err)
	}
	if _, err := os.Stat(cfg.CA.Cert); err != nil {
		t.Errorf("cert not created: %v", err)
	}

	// parse certificate
	pemBytes, err := ioutil.ReadFile(cfg.CA.Cert)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("failed to decode pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Errorf("certificate is not CA")
	}
}

func TestInitCA_OverwriteFalse(t *testing.T) {
	dir := t.TempDir()
	cfg := ca.Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")

	// create dummy files
	os.MkdirAll(filepath.Dir(cfg.CA.Key), 0755)
	os.WriteFile(cfg.CA.Key, []byte("dummy"), 0644)
	os.WriteFile(cfg.CA.Cert, []byte("dummy"), 0644)

	if err := ca.InitCA(cfg); err == nil {
		t.Fatalf("expected error when files exist without overwrite")
	}
}

func TestInitCA_OverwriteTrue(t *testing.T) {
	dir := t.TempDir()
	cfg := ca.Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	os.MkdirAll(filepath.Dir(cfg.CA.Key), 0755)
	os.WriteFile(cfg.CA.Key, []byte("dummy"), 0644)
	os.WriteFile(cfg.CA.Cert, []byte("dummy"), 0644)
	cfg.Overwrite = true
	if err := ca.InitCA(cfg); err != nil {
		t.Fatalf("overwrite true: %v", err)
	}
}

func TestInitCA_InvalidAlgo(t *testing.T) {
	dir := t.TempDir()
	cfg := ca.Config{}
	cfg.CA.Key = filepath.Join(dir, "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "cert.pem")
	cfg.DefaultAlgo = "bad"
	if err := ca.InitCA(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestInitCA_WriteKeyError(t *testing.T) {
	dir := t.TempDir()
	cfg := ca.Config{}
	cfg.CA.Key = dir
	cfg.CA.Cert = filepath.Join(dir, "cert.pem")
	cfg.Overwrite = true
	if err := ca.InitCA(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestInitCA_DefaultPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	cfg := ca.Config{Overwrite: true}
	if err := ca.InitCA(cfg); err != nil {
		t.Fatalf("default path: %v", err)
	}
	if _, err := os.Stat(filepath.Join("certs", "ca", "key.pem")); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKeyVariants(t *testing.T) {
	if _, _, err := ca.GenerateKey("rsa"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ca.GenerateKey("ecdsa"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ca.GenerateKey("ed25519"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteAndExists(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.pem")
	priv, _, _ := ca.GenerateKey("rsa")
	if err := ca.WriteKey(keyPath, priv); err != nil {
		t.Fatal(err)
	}
	if !ca.Exists(keyPath) {
		t.Fatal("file should exist")
	}
}

func TestWriteKey_All(t *testing.T) {
	dir := t.TempDir()
	algos := []string{"rsa", "ecdsa", "ed25519"}
	for _, a := range algos {
		priv, _, err := ca.GenerateKey(a)
		if err != nil {
			t.Fatalf("key gen %s: %v", a, err)
		}
		path := filepath.Join(dir, a+".pem")
		if err := ca.WriteKey(path, priv); err != nil {
			t.Fatalf("write %s: %v", a, err)
		}
	}
}

func TestPkixName(t *testing.T) {
	n := ca.PkixName()
	if n.CommonName == "" {
		t.Fatal("empty cn")
	}
}

func TestEllipticP256(t *testing.T) {
	c := ca.EllipticP256()
	if c.Params().Name != "P-256" {
		t.Fatal("not p256")
	}
}

func TestWriteKeyError(t *testing.T) {
	if err := ca.WriteKey(filepath.Join(t.TempDir(), "x"), struct{}{}); err == nil {
		t.Fatal("expected error")
	}
}

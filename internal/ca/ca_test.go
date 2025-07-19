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

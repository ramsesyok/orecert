package ca

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestExists(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if Exists(f) {
		t.Fatalf("should not exist")
	}
	os.WriteFile(f, []byte("a"), 0600)
	if !Exists(f) {
		t.Fatalf("should exist")
	}
}

func TestGenerateKey_All(t *testing.T) {
	if _, _, err := GenerateKey("rsa"); err != nil {
		t.Fatalf("rsa: %v", err)
	}
	if _, _, err := GenerateKey("ecdsa"); err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	if _, _, err := GenerateKey("ed25519"); err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	if _, _, err := GenerateKey("bad"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestGenerateKey_Error(t *testing.T) {
	r := rand.Reader
	defer func() { rand.Reader = r }()
	rand.Reader = bytes.NewReader(nil)
	if _, _, err := GenerateKey("rsa"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestWriteKey_Unsupported(t *testing.T) {
	if err := WriteKey(filepath.Join(t.TempDir(), "k"), struct{}{}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestEllipticP256(t *testing.T) {
	if EllipticP256() == nil {
		t.Fatalf("nil curve")
	}
}

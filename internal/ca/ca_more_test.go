package ca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExists(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if exists(f) {
		t.Fatalf("should not exist")
	}
	os.WriteFile(f, []byte("a"), 0600)
	if !exists(f) {
		t.Fatalf("should exist")
	}
}

func TestGenerateKey_All(t *testing.T) {
	if _, _, err := generateKey("rsa"); err != nil {
		t.Fatalf("rsa: %v", err)
	}
	if _, _, err := generateKey("ecdsa"); err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	if _, _, err := generateKey("ed25519"); err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	if _, _, err := generateKey("bad"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestWriteKey_Unsupported(t *testing.T) {
	if err := writeKey(filepath.Join(t.TempDir(), "k"), struct{}{}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestEllipticP256(t *testing.T) {
	if ellipticP256() == nil {
		t.Fatalf("nil curve")
	}
}

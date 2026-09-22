//go:build !windows

package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretOutputPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Write([]File{{Path: path, Data: []byte("secret"), Mode: 0600}}, true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("秘密ファイルの権限: %v", info.Mode())
	}
}

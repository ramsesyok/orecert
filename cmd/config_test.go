package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFailsClosed(t *testing.T) {
	dir := t.TempDir()
	for _, data := range []string{"pkcs12_password: prompt:\n", "overwrite: tru\n", "unknown: 1\n", "default_days: -1\n", "{}\n---\n{}\n", "null\n"} {
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Errorf("設定を拒否しませんでした: %q", data)
		}
	}
	if _, err := loadConfig(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("設定欠落")
	}
}

func TestProfileUnknownFieldFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(path, []byte("cn: host\nencrypt_keey: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProfile(path); err == nil {
		t.Fatal("暗号化設定の誤記を拒否しませんでした")
	}
}

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidation(t *testing.T) {
	for _, cn := range []string{"", ".", "..", "../outside", "a/b", "a\\b", "CA", "ca", "host.", "CON", "nul.txt", "LPT1", "COM9", "a:b", " host", "a\x00b"} {
		if ValidateCN(cn) == nil {
			t.Errorf("許可されました: %q", cn)
		}
	}
	if ValidateCN("localhost") != nil {
		t.Fatal("正常なCN")
	}
	t.Chdir(t.TempDir())
	if _, err := CertificateDir("host", "certs/host/key.pem"); err == nil {
		t.Fatal("CAパスとの衝突")
	}
	if _, err := CertificateDir("host", "certs/ca/key.pem"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteRollback(t *testing.T) {
	t.Chdir(t.TempDir())
	files := []File{{"certs/key", []byte("old key"), 0600}, {"certs/cert", []byte("old cert"), 0644}}
	if err := Write(files, false); err != nil {
		t.Fatal(err)
	}
	if err := Write(files, false); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	newer := []File{{files[0].Path, []byte("new key"), 0600}, {files[1].Path, []byte("new cert"), 0644}}
	count := 0
	err := write(newer, true, func(a, b string) error {
		count++
		if count == 4 {
			return errors.New("書き込み障害")
		}
		return os.Rename(a, b)
	})
	if err == nil {
		t.Fatal("障害が伝播しませんでした")
	}
	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil || string(data) != string(f.Data) {
			t.Fatalf("復元失敗: %s %v", f.Path, err)
		}
	}
	if err := Write(newer, true); err != nil {
		t.Fatal(err)
	}
	if err := Check([]File{files[0], files[0]}, true); err == nil {
		t.Fatal("重複パス")
	}
	if err := Check([]File{{Path: "certs"}}, true); err == nil {
		t.Fatal("ディレクトリ")
	}
	if err := os.Symlink("certs", "linked"); err == nil {
		if err := Check([]File{{Path: filepath.Join("linked", "key")}}, true); err == nil {
			t.Fatal("リンク")
		}
	}
}

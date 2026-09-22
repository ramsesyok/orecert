// Package safefile は証明書の出力先検証と安全なファイル更新を提供します。
package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var ErrInvalidCN = errors.New("invalid cn")
var ErrExists = errors.New("files exist and overwrite disabled")

func ValidateCN(cn string) error {
	if cn == "" || cn == "." || strings.Contains(cn, "..") || strings.ContainsAny(cn, "/\\:<>\"|?*\x00") || strings.TrimSpace(cn) != cn || strings.HasSuffix(cn, ".") || strings.EqualFold(cn, "ca") {
		return ErrInvalidCN
	}
	for _, r := range cn {
		if r < 32 {
			return ErrInvalidCN
		}
	}
	name := strings.ToUpper(strings.SplitN(cn, ".", 2)[0])
	if name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || len(name) == 4 && (strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) && name[3] >= '1' && name[3] <= '9' {
		return ErrInvalidCN
	}
	return nil
}

// CertificateDir はCA領域との衝突とリンク経由の出力を拒否します。
func CertificateDir(cn string, protected ...string) (string, error) {
	if err := ValidateCN(cn); err != nil {
		return "", err
	}
	base := filepath.Join("certs", cn)
	if err := noLinks(base); err != nil {
		return "", err
	}
	for _, p := range protected {
		if p == "" {
			continue
		}
		a, err := filepath.Abs(base)
		if err != nil {
			return "", err
		}
		b, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		if runtime.GOOS == "windows" {
			a = strings.ToLower(a)
			b = strings.ToLower(b)
		}
		rel, err := filepath.Rel(a, b)
		if err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return "", errors.New("certificate output conflicts with CA files")
		}
	}
	return base, nil
}

func noLinks(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for p := abs; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not allowed: %s", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

type File struct {
	Path string
	Data []byte
	Mode os.FileMode
}

// Check は書き込み前に全出力の衝突・種別を検証します。
func Check(files []File, overwrite bool) error {
	seen := map[string]bool{}
	for _, f := range files {
		abs, err := filepath.Abs(f.Path)
		if err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			abs = strings.ToLower(abs)
		}
		if seen[abs] {
			return errors.New("duplicate output paths")
		}
		seen[abs] = true
		if err := noLinks(f.Path); err != nil {
			return err
		}
		info, err := os.Lstat(f.Path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !overwrite {
			return ErrExists
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output is not a regular file: %s", f.Path)
		}
	}
	return nil
}

// Write は全ファイルを準備してから更新し、通常のI/O失敗時は元に戻します。
// 電源断と同一出力先への並行実行はトランザクションの対象外です。
func Write(files []File, overwrite bool) error { return write(files, overwrite, os.Rename) }

func write(files []File, overwrite bool, rename func(string, string) error) (result error) {
	if err := Check(files, overwrite); err != nil {
		return err
	}
	staged := make([]string, len(files))
	backups := make([]string, len(files))
	installed := make([]bool, len(files))
	defer func() {
		failed := result != nil
		for i := len(files) - 1; i >= 0; i-- {
			if failed {
				if installed[i] {
					result = errors.Join(result, os.Remove(files[i].Path))
				}
				if backups[i] != "" {
					if err := os.Rename(backups[i], files[i].Path); err != nil {
						result = errors.Join(result, fmt.Errorf("restore backup %s: %w", backups[i], err))
					} else {
						backups[i] = ""
					}
				}
			}
			if staged[i] != "" {
				_ = os.Remove(staged[i])
			}
			if !failed && backups[i] != "" {
				if err := os.Remove(backups[i]); err != nil {
					result = errors.Join(result, err)
				}
			}
		}
	}()
	for i, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.Path), 0700); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".orecert-*")
		if err != nil {
			return err
		}
		staged[i] = tmp.Name()
		// 書き込み前に秘密鍵を含む一時ファイルのアクセスを制限します。
		if err := restrict(tmp.Name(), f.Mode); err != nil {
			_ = tmp.Close()
			return err
		}
		_, err = tmp.Write(f.Data)
		if err == nil {
			err = tmp.Sync()
		}
		err = errors.Join(err, tmp.Close())
		if err != nil {
			return err
		}
	}
	// 全ファイルの準備後にも再検証し、途中生成物による衝突を防ぎます。
	if err := Check(files, overwrite); err != nil {
		return err
	}
	for i, f := range files {
		if _, err := os.Lstat(f.Path); err == nil {
			backup, err := os.CreateTemp(filepath.Dir(f.Path), ".orecert-backup-*")
			if err != nil {
				return err
			}
			name := backup.Name()
			if err := backup.Close(); err != nil {
				return err
			}
			if err := os.Remove(name); err != nil {
				return err
			}
			if err := rename(f.Path, name); err != nil {
				return err
			}
			backups[i] = name
		}
		if err := rename(staged[i], f.Path); err != nil {
			return err
		}
		staged[i] = ""
		installed[i] = true
	}
	return nil
}

package safefile

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretOutputACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	// 公開状態の既存ファイルも上書き後に秘密用ACLに置き換わります。
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Write([]File{{Path: path, Data: []byte("secret"), Mode: 0600}}, true); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	if !strings.Contains(sddl, "D:P") || strings.Count(sddl, "(A;") != 2 || !strings.Contains(sddl, ";;;SY)") || !strings.Contains(sddl, ";;;"+user.User.Sid.String()+")") {
		t.Fatalf("意図しないACL: %s", sddl)
	}
}

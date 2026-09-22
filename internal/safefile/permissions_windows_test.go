package safefile

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
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
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("ACLの継承が無効ではありません: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("意図しないACL: %s (%v)", descriptor.String(), err)
	}
	// SIDの短縮表記（管理者のLAなど）に依存せず、実際の許可対象と権限を検査します。
	want := map[string]bool{"S-1-5-18": true, user.User.Sid.String(): true}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != 0x1f01ff || !want[sid] {
			t.Fatalf("意図しないアクセス許可: %s", descriptor.String())
		}
		delete(want, sid)
	}
	if len(want) != 0 {
		t.Fatalf("必要なアクセス許可がありません: %v", want)
	}
}

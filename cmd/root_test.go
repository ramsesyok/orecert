package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func runCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(args)
	err := root.Execute()
	return output.String(), err
}
func requireCommand(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runCommand(t, args...)
	if err != nil {
		t.Fatalf("%v: %v (%s)", args, err, out)
	}
	return out
}
func setupCLI(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	writeTestFile(t, ".orecert.yaml", "default_algo: ecdsa\npkcs12_password: file:password.txt\n")
	writeTestFile(t, "password.txt", "test secret\n")
	writeTestFile(t, "host.yaml", "cn: localhost\nsan: [DNS:localhost, IP:127.0.0.1]\n")
}

func TestCommandLifecycle(t *testing.T) {
	setupCLI(t)
	requireCommand(t, "init-ca")
	requireCommand(t, "issue", "host.yaml", "-t", "both")
	requireCommand(t, "verify", "host.yaml", "--hostname", "localhost", "-t", "both")
	requireCommand(t, "bundle", "host.yaml", "-t", "pkcs", "-t", "jks")
	for _, path := range []string{"certs/localhost/key.pem", "certs/localhost/csr.pem", "certs/localhost/cert.pem", "certs/localhost/fullchain.pem", "certs/localhost/meta.json", "certs/localhost/bundle.p12", "certs/localhost/bundle.jks"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init-ca"}, {"issue", "host.yaml"}, {"bundle", "host.yaml"}, {"verify", "host.yaml", "--hostname", "wrong"}} {
		if _, err := runCommand(t, args...); err == nil {
			t.Fatalf("失敗するべき操作: %v", args)
		}
	}
	requireCommand(t, "revoke", "host.yaml")
	requireCommand(t, "revoke", "host.yaml")
	requireCommand(t, "refresh-crl")
	if _, err := runCommand(t, "verify", "host.yaml"); err == nil {
		t.Fatal("失効済み証明書")
	}
	out := requireCommand(t, "verify", "host.yaml", "--skip-crl")
	if !strings.Contains(out, "WARN:") {
		t.Fatal("省略の警告")
	}
}

func TestEncryptedKeyCLI(t *testing.T) {
	setupCLI(t)
	requireCommand(t, "init-ca")
	writeTestFile(t, "host.yaml", "cn: encrypted\nalgo: ed25519\nencrypt_key: true\nkey_pass: file:password.txt\n")
	requireCommand(t, "issue", "host.yaml", "-t", "client")
	key, err := os.ReadFile("certs/encrypted/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(key, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		t.Fatal("秘密鍵が暗号化されていません")
	}
	requireCommand(t, "verify", "host.yaml")
	out := requireCommand(t, "bundle", "host.yaml", "--legacy")
	if !strings.Contains(out, "WARN:") {
		t.Fatal("互換方式の警告")
	}
	writeTestFile(t, ".orecert.yaml", "default_algo: ecdsa\npkcs12_password: file:password.txt\noverwrite: true\njson_output: true\n")
	out = requireCommand(t, "bundle", "host.yaml")
	var result map[string]any
	if json.Unmarshal([]byte(out), &result) != nil || result["status"] != "ok" {
		t.Fatal(out)
	}
}

func TestCommandsFailClosed(t *testing.T) {
	setupCLI(t)
	for _, args := range [][]string{{"init-ca", "extra"}, {"issue"}, {"bundle"}, {"verify"}, {"revoke"}, {"refresh-crl", "extra"}, {"unknown"}, {"issue", "missing"}, {"bundle", "missing"}, {"verify", "missing"}, {"revoke", "missing"}, {"verify", "host.yaml"}, {"revoke", "host.yaml"}, {"refresh-crl"}, {"bundle", "host.yaml"}, {"issue", "host.yaml"}} {
		if _, err := runCommand(t, args...); err == nil {
			t.Errorf("エラーになりませんでした: %v", args)
		}
	}
	writeTestFile(t, "bad.yaml", "pkcs12_password: prompt:\n")
	if _, err := runCommand(t, "init-ca", "-c", "bad.yaml"); err == nil {
		t.Fatal("不正設定で生成しました")
	}
	if _, err := os.Stat("certs/ca/key.pem"); !os.IsNotExist(err) {
		t.Fatal("失敗時にCAが生成されました")
	}
	requireCommand(t, "init-ca")
	writeTestFile(t, "host.yaml", "cn: ../outside\n")
	if _, err := runCommand(t, "bundle", "host.yaml"); err == nil {
		t.Fatal("パス検証")
	}
}

func TestConfigurationAndHelp(t *testing.T) {
	setupCLI(t)
	t.Setenv("DEFAULT_ALGO", "invalid")
	cfg, err := loadConfig(".orecert.yaml")
	if err != nil || cfg.DefaultAlgo != "ecdsa" {
		t.Fatalf("環境変数に影響されています: %v", err)
	}
	requireCommand(t, "--help")
	requireCommand(t, "version", "-c", "missing")
	writeTestFile(t, ".orecert.yaml", "log_level: quiet\ndefault_algo: ecdsa\n")
	if out := requireCommand(t, "init-ca"); out != "" {
		t.Fatal(out)
	}
	for _, data := range []string{"default_algo: invalid\n", "ca: {key: ''}\n", "pkcs12_password: ''\n", "log_level: invalid\n", ""} {
		writeTestFile(t, "invalid.yaml", data)
		if _, err := loadConfig("invalid.yaml"); err == nil {
			t.Fatalf("無効な設定: %q", data)
		}
	}
}

func TestExecuteError(t *testing.T) {
	if os.Getenv("EXECUTE_ERROR") == "1" {
		os.Args = []string{"orecert", "unknown"}
		Execute()
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestExecuteError$")
	command.Env = append(os.Environ(), "EXECUTE_ERROR=1")
	if err := command.Run(); err == nil {
		t.Fatal("エラー終了していません")
	}
}

func TestSampleConfiguration(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("..", ".orecert.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PKCS12Password != "prompt:" {
		t.Fatal("対話入力が既定ではありません")
	}
}

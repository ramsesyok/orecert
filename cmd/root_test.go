package cmd

import (
	"os"
	"path/filepath"
	
	"orecert/internal/ca"
	"testing"
)

func TestExecuteHelp(t *testing.T) {
	rootCmd.SetArgs([]string{"--help"})
	Execute()
}

func TestInitConfig(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "cfg.yaml")
	if err != nil {
		t.Fatalf("tmp: %v", err)
	}
	tmp.WriteString("pkcs12_password: pass\n")
	tmp.Close()
	cfgFile = tmp.Name()
	initConfig()
)

func TestExecute_Help(t *testing.T) {
	rootCmd.SetArgs([]string{"--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute help: %v", err)
	}
}

func TestIssueCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := ca.Config{}
	cfg.CA.Key = filepath.Join(dir, "certs", "ca", "key.pem")
	cfg.CA.Cert = filepath.Join(dir, "certs", "ca", "cert.pem")
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := ca.InitCA(cfg); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(".orecert.yaml", []byte("{}"), 0644)
	profile := filepath.Join(dir, "p.yml")
	os.WriteFile(profile, []byte("cn: test"), 0644)

	rootCmd.SetArgs([]string{"-c", ".orecert.yaml", "issue", profile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute issue: %v", err)
	}
}

func TestOtherCommands(t *testing.T) {
	cmds := [][]string{
		{"version"},
		{"bundle"},
		{"verify"},
		{"revoke"},
	}
	for _, c := range cmds {
		rootCmd.SetArgs(c)
		rootCmd.Execute()
	}
}

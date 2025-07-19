package cmd

import (
	"os"
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
}

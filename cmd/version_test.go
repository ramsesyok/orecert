package cmd

import (
	"bytes"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	versionCmd.SetOut(buf)
	versionCmd.Run(versionCmd, []string{})
	if buf.String() != Version+"\n" {
		t.Fatalf("version output mismatch: %s", buf.String())
	}
}

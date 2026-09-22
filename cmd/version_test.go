package cmd

import (
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	out := requireCommand(t, "version")
	if strings.TrimSpace(out) != Version {
		t.Fatal(out)
	}
}

package main

import (
	"os"
	"testing"
)

func TestMainCommand(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	os.Args = []string{"orecert", "--help"}
	main()
}

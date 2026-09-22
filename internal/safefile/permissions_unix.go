//go:build !windows

package safefile

import "os"

func restrict(path string, mode os.FileMode) error { return os.Chmod(path, mode) }

//go:build windows

package winsys

import (
	"os"
	"path/filepath"
)

// ProgramDataDir returns the per-app data dir under %ProgramData%.
// WHY %ProgramData% (not the user profile): the elevated engine writes it and
// a non-elevated `detour status` reads it; ProgramData is world-readable by
// default on Windows, which is exactly the ACL shape M1 needs.
func ProgramDataDir(app string) string {
	root := os.Getenv("ProgramData")
	if root == "" {
		root = `C:\ProgramData`
	}
	d := filepath.Join(root, app)
	_ = os.MkdirAll(d, 0o755)
	return d
}

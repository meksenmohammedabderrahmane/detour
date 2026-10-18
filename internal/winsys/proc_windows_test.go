//go:build windows

package winsys

import (
	"os"
	"strings"
	"testing"
)

func TestExePathHandleLessAndDos(t *testing.T) {
	pid := uint32(os.Getpid())
	path, ok := ExePath(pid)
	if !ok || path == "" {
		t.Fatalf("ExePath(%d) failed: ok=%v, path=%q", pid, ok, path)
	}
	t.Logf("ExePath(%d) = %q", pid, path)
	if !strings.HasPrefix(path, "C:\\") {
		t.Errorf("expected C:\\ prefix, got %q", path)
	}
	if !strings.Contains(strings.ToLower(path), "winsys.test.exe") {
		t.Errorf("expected path containing winsys.test.exe, got %q", path)
	}
}

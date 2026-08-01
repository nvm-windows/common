//go:build windows

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "node-shim.exe")
	replacement := filepath.Join(dir, "node-shim-new.exe")

	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile(target): %v", err)
	}
	if err := os.WriteFile(replacement, []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteFile(replacement): %v", err)
	}

	if err := ReplaceExecutable(replacement, target); err != nil {
		t.Fatalf("ReplaceExecutable() error = %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target): %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("target content = %q, want %q", got, "new")
	}
	if _, err := os.Stat(replacement); !os.IsNotExist(err) {
		t.Fatalf("replacement still exists after replace: %v", err)
	}
}

func TestReplaceExecutableCreatesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "missing-shim.exe")
	replacement := filepath.Join(dir, "node-shim-new.exe")

	if err := os.WriteFile(replacement, []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteFile(replacement): %v", err)
	}

	if err := ReplaceExecutable(replacement, target); err != nil {
		t.Fatalf("ReplaceExecutable() error = %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target): %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("target content = %q, want %q", got, "new")
	}
}

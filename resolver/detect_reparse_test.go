package resolver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFileIsReparseRegular(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".nvmrc")
	if err := os.WriteFile(path, []byte("20.11.0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if detectFileIsReparse(path) {
		t.Fatal("regular file reported as reparse")
	}
}

func TestDetectFileIsReparseSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.txt")
	link := filepath.Join(dir, ".nvmrc")
	if err := os.WriteFile(target, []byte("token=leak\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not permitted: %v", err)
	}
	if !detectFileIsReparse(link) {
		t.Fatal("symlink detect file not reported as reparse")
	}
}

func TestDetectFileIsReparseMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.nvmrc")
	if detectFileIsReparse(path) {
		t.Fatal("missing path reported as reparse")
	}
}

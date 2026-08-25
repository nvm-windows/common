//go:build windows

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProgramDataNotSafeManagedRoot(t *testing.T) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		t.Skip("ProgramData not set")
	}
	path := filepath.Join(pd, "nvm", "installs")
	if isUnderSafeManagedRoot(path) {
		t.Fatalf("ProgramData path %q must not be treated as a safe managed root", path)
	}
}

func TestCheckVersionDirTrustMissingOK(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "v1.2.3")
	if err := CheckVersionDirTrust(missing); err != nil {
		t.Fatalf("CheckVersionDirTrust(missing) = %v", err)
	}
}

func TestCheckVersionDirTrustNormalDirectoryOK(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "v1.2.3")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := CheckVersionDirTrust(dir); err != nil {
		t.Fatalf("CheckVersionDirTrust(normal directory) = %v", err)
	}
}

func TestCheckVersionDirTrustRejectsReparse(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	link := filepath.Join(root, "v9.9.9")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not permitted: %v", err)
	}
	err := CheckVersionDirTrust(link)
	if err == nil {
		t.Fatal("CheckVersionDirTrust(reparse) = nil, want error")
	}
}

func TestAssertNoReparseBetweenOK(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := AssertNoReparseBetween(root, nested); err != nil {
		t.Fatalf("AssertNoReparseBetween: %v", err)
	}
}

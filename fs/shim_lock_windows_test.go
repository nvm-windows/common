//go:build windows

package fs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestApplyHardenedDACLDoesNotCrash(t *testing.T) {
	dir := `C:\nvm-shim-lock-test`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	if err := applyHardenedDACL(dir); err != nil {
		t.Fatalf("applyHardenedDACL: %v", err)
	}
}

func TestSetProtectedObjectDACLDoesNotCrash(t *testing.T) {
	dir := t.TempDir()

	entries, release, err := hardenedExplicitAccess()
	if err != nil {
		t.Fatalf("hardenedExplicitAccess: %v", err)
	}
	defer release()

	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}

	if err := setProtectedObjectDACL(dir, dacl); err != nil {
		t.Fatalf("setProtectedObjectDACL: %v", err)
	}
}

func TestShimDirectoryLockBlocksManualPlant(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, ".shim")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	if err := LockShimDirectory(shimDir); err != nil {
		t.Fatalf("LockShimDirectory: %v", err)
	}
	t.Cleanup(func() { _ = UnlockShimDirectory(shimDir) })

	evil := filepath.Join(shimDir, "evil.exe")
	if err := os.WriteFile(evil, []byte("bad"), 0o644); err == nil {
		t.Fatal("WriteFile to locked .shim succeeded, want failure")
	}
}

func TestRunWithRuntimeShimWriteAllowsShimMaintenance(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, ".shim")
	proxyPath := filepath.Join(root, "proxy.exe")

	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte("proxy"), 0o644); err != nil {
		t.Fatalf("WriteFile(proxy): %v", err)
	}

	err := RunWithRuntimeShimWrite(shimDir, proxyPath, func() error {
		return os.WriteFile(filepath.Join(shimDir, "npm.exe"), []byte("proxy"), 0o644)
	})
	if err != nil {
		t.Fatalf("RunWithRuntimeShimWrite: %v", err)
	}

	if _, err := os.Stat(filepath.Join(shimDir, "npm.exe")); err != nil {
		t.Fatalf("Stat(npm.exe): %v", err)
	}

	if err := LockShimDirectory(shimDir); err != nil {
		t.Fatalf("LockShimDirectory after write window: %v", err)
	}
	t.Cleanup(func() {
		_ = UnlockShimDirectory(shimDir)
		_ = UnlockProxyExecutable(proxyPath)
	})

	evil := filepath.Join(shimDir, "evil.exe")
	if err := os.WriteFile(evil, []byte("bad"), 0o644); err == nil {
		t.Fatal("WriteFile to re-locked .shim succeeded, want failure")
	}
}

func TestRunWithRuntimeShimWriteUpdatesProxy(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, ".shim")
	proxyPath := filepath.Join(root, "proxy.exe")

	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile(proxy): %v", err)
	}

	err := RunWithRuntimeShimWrite(shimDir, proxyPath, func() error {
		return os.WriteFile(proxyPath, []byte("new"), 0o644)
	})
	if err != nil {
		t.Fatalf("RunWithRuntimeShimWrite: %v", err)
	}

	data, err := os.ReadFile(proxyPath)
	if err != nil {
		t.Fatalf("ReadFile(proxy): %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("proxy content = %q, want %q", data, "new")
	}

	if err := LockProxyExecutable(proxyPath); err != nil {
		t.Fatalf("LockProxyExecutable: %v", err)
	}
	t.Cleanup(func() {
		_ = UnlockShimDirectory(shimDir)
		_ = UnlockProxyExecutable(proxyPath)
	})

	if err := os.WriteFile(proxyPath, []byte("tampered"), 0o644); err == nil {
		t.Fatal("WriteFile to locked proxy succeeded, want failure")
	}
}

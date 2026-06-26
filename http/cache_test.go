package http

import (
	"path/filepath"
	"testing"
)

func TestCacheDirPathUsesInstallRootParent(t *testing.T) {
	t.Setenv("LOCALAPPDATA", `C:\Users\test\AppData\Local`)

	want := filepath.Join(`C:\Users\test\AppData\Local\Author Software\nvm`, ".cache", httpCacheRoot)
	got := cacheDirPath(
		`C:\Program Files\Author Software\nvm\nvm.exe`,
		`%LOCALAPPDATA%\Author Software\nvm\installs`,
	)
	if got != want {
		t.Fatalf("cacheDirPath() = %q, want %q", got, want)
	}
}

func TestCacheDirPathFallsBackToExecutableDirectory(t *testing.T) {
	got := cacheDirPath(`C:\Tools\nvm\nvm.exe`, "")
	want := filepath.Join(`C:\Tools\nvm`, ".cache", httpCacheRoot)
	if got != want {
		t.Fatalf("cacheDirPath() = %q, want %q", got, want)
	}
}

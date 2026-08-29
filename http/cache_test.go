package http

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestFindCachedForURLInPicksNewest(t *testing.T) {
	cacheDir := t.TempDir()
	rawURL := "https://nodejs.org/dist/index.tab"
	normalized, err := normalizeURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	prefix := sanitizeFileName(normalized + "__")
	older := filepath.Join(cacheDir, prefix+"old")
	newer := filepath.Join(cacheDir, prefix+"new")
	if err := os.WriteFile(older, []byte("old-body"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(newer, []byte("new-body"), 0o644); err != nil {
		t.Fatal(err)
	}

	content, etag, _, ok := findCachedForURLIn(cacheDir, rawURL)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(content) != "new-body" {
		t.Fatalf("content = %q", content)
	}
	if etag != "new" {
		t.Fatalf("etag = %q, want new", etag)
	}
}

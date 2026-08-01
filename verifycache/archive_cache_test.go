//go:build windows

package verifycache

import (
	"common/registry"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupSignedDownloadArchive(t *testing.T, dataRoot string, content []byte) string {
	t.Helper()

	cacheDir := filepath.Join(dataRoot, ".cache", "versions")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(cacheDir) error = %v", err)
	}

	archivePath := filepath.Join(cacheDir, "node-v22.0.0-win-x64.7z")
	if err := os.WriteFile(archivePath, content, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := signDownloadArchiveCache(dataRoot, archivePath); err != nil {
		t.Fatalf("signDownloadArchiveCache() error = %v", err)
	}
	return archivePath
}

func downloadCacheEntryBase(t *testing.T, archivePath string) string {
	t.Helper()

	cacheKey, err := cacheKeyForPath(archivePath)
	if err != nil {
		t.Fatalf("cacheKeyForPath() error = %v", err)
	}
	return downloadCacheEntryRoot(cacheKey)
}

func TestSignDownloadArchiveCacheCreatesRegistryEntry(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	cacheDir := filepath.Join(dataRoot, ".cache", "versions")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(cacheDir) error = %v", err)
	}

	archivePath := filepath.Join(cacheDir, "node-v22.0.0-win-x64.7z")
	if err := os.WriteFile(archivePath, []byte("verified archive bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := signDownloadArchiveCache(dataRoot, archivePath); err != nil {
		t.Fatalf("signDownloadArchiveCache() error = %v", err)
	}

	cacheKey, err := cacheKeyForPath(archivePath)
	if err != nil {
		t.Fatalf("cacheKeyForPath() error = %v", err)
	}

	entry, err := readDownloadCacheEntry(cacheKey)
	if err != nil {
		t.Fatalf("readDownloadCacheEntry() error = %v", err)
	}
	if entry["Path"] == nil || entry["Sig"] == nil || entry["Digest"] == nil {
		t.Fatalf("readDownloadCacheEntry() = %#v, want Path, Digest, and Sig values", entry)
	}

	if err := verifyStoredArchiveSignature(dataRoot, entry); err != nil {
		t.Fatalf("verifyStoredArchiveSignature() error = %v", err)
	}

	if err := verifyDownloadArchiveCache(dataRoot, archivePath); err != nil {
		t.Fatalf("verifyDownloadArchiveCache() error = %v", err)
	}
}

func TestVerifyDownloadArchiveCacheRejectsTamperedArchive(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	cacheDir := filepath.Join(dataRoot, ".cache", "versions")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(cacheDir) error = %v", err)
	}

	archivePath := filepath.Join(cacheDir, "node-v22.0.0-win-x64.7z")
	if err := os.WriteFile(archivePath, []byte("verified archive bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := signDownloadArchiveCache(dataRoot, archivePath); err != nil {
		t.Fatalf("signDownloadArchiveCache() error = %v", err)
	}

	if err := os.WriteFile(archivePath, []byte("tampered archive bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile(tampered) error = %v", err)
	}

	if err := verifyDownloadArchiveCache(dataRoot, archivePath); err == nil {
		t.Fatal("verifyDownloadArchiveCache() error = nil, want mismatch")
	}
}

func TestClearDownloadArchiveCacheRemovesEntry(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	cacheDir := filepath.Join(dataRoot, ".cache", "versions")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(cacheDir) error = %v", err)
	}

	archivePath := filepath.Join(cacheDir, "node-v22.0.0-win-x64.7z")
	if err := os.WriteFile(archivePath, []byte("verified archive bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := signDownloadArchiveCache(dataRoot, archivePath); err != nil {
		t.Fatalf("signDownloadArchiveCache() error = %v", err)
	}

	if err := ClearDownloadArchiveCache(archivePath); err != nil {
		t.Fatalf("ClearDownloadArchiveCache() error = %v", err)
	}

	cacheKey, err := cacheKeyForPath(archivePath)
	if err != nil {
		t.Fatalf("cacheKeyForPath() error = %v", err)
	}
	entry, err := readDownloadCacheEntry(cacheKey)
	if err != nil {
		t.Fatalf("readDownloadCacheEntry() error = %v", err)
	}
	if len(entry) != 0 {
		t.Fatalf("readDownloadCacheEntry() after clear = %#v, want empty", entry)
	}
}

func TestCanonicalArchivePayloadRegression(t *testing.T) {
	payload, err := canonicalArchivePayload(`C:\nvm\.cache\versions\node-v22.7z`, 12345, 9876543210, "abc123")
	if err != nil {
		t.Fatalf("canonicalArchivePayload() error = %v", err)
	}
	want := "v2-archive\nc:\\nvm\\.cache\\versions\\node-v22.7z\n12345\n9876543210\nabc123"
	if payload != want {
		t.Fatalf("canonicalArchivePayload() = %q, want %q", payload, want)
	}
}

func TestVerifyDownloadArchiveCacheMiss(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	cacheDir := filepath.Join(dataRoot, ".cache", "versions")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(cacheDir) error = %v", err)
	}

	archivePath := filepath.Join(cacheDir, "node-v22.0.0-win-x64.7z")
	if err := os.WriteFile(archivePath, []byte("no registry entry"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := verifyDownloadArchiveCache(dataRoot, archivePath); !errors.Is(err, ErrDownloadCacheMiss) {
		t.Fatalf("verifyDownloadArchiveCache() error = %v, want ErrDownloadCacheMiss", err)
	}
}

func TestVerifyDownloadArchiveCacheRejectsMtimeMismatch(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	archivePath := setupSignedDownloadArchive(t, dataRoot, []byte("mtime-sensitive archive"))

	changed := time.Now().Add(48 * time.Hour)
	if err := os.Chtimes(archivePath, changed, changed); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	err := verifyDownloadArchiveCache(dataRoot, archivePath)
	if err == nil {
		t.Fatal("verifyDownloadArchiveCache() error = nil, want mtime mismatch")
	}
	if !strings.Contains(err.Error(), "modification time mismatch") {
		t.Fatalf("verifyDownloadArchiveCache() error = %v, want modification time mismatch", err)
	}
}

func TestVerifyDownloadArchiveCacheRejectsSizeMismatch(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	archivePath := setupSignedDownloadArchive(t, dataRoot, []byte("size-sensitive archive"))

	f, err := os.OpenFile(archivePath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	if _, err := f.WriteString("x"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	err = verifyDownloadArchiveCache(dataRoot, archivePath)
	if err == nil {
		t.Fatal("verifyDownloadArchiveCache() error = nil, want size mismatch")
	}
	if !strings.Contains(err.Error(), "size mismatch") && !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("verifyDownloadArchiveCache() error = %v, want size or digest mismatch", err)
	}
}

func TestVerifyDownloadArchiveCacheRejectsWrongSchemaVersion(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	archivePath := setupSignedDownloadArchive(t, dataRoot, []byte("versioned archive"))
	base := downloadCacheEntryBase(t, archivePath)

	if err := registry.Put(uint32(1), base+"/Version"); err != nil {
		t.Fatalf("Put(Version) error = %v", err)
	}

	err := verifyDownloadArchiveCache(dataRoot, archivePath)
	if err == nil {
		t.Fatal("verifyDownloadArchiveCache() error = nil, want unsupported schema version")
	}
	if !strings.Contains(err.Error(), "unsupported download cache schema version") {
		t.Fatalf("verifyDownloadArchiveCache() error = %v, want unsupported schema version", err)
	}
}

func TestVerifyDownloadArchiveCacheRejectsPathMismatch(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	archivePath := setupSignedDownloadArchive(t, dataRoot, []byte("path-bound archive"))
	base := downloadCacheEntryBase(t, archivePath)

	if err := registry.Put(`C:\other\cache\node-v22.0.0-win-x64.7z`, base+"/Path"); err != nil {
		t.Fatalf("Put(Path) error = %v", err)
	}

	err := verifyDownloadArchiveCache(dataRoot, archivePath)
	if err == nil {
		t.Fatal("verifyDownloadArchiveCache() error = nil, want path mismatch")
	}
	if !strings.Contains(err.Error(), "path mismatch") {
		t.Fatalf("verifyDownloadArchiveCache() error = %v, want path mismatch", err)
	}
}

func TestVerifyDownloadArchiveCacheRejectsForgedSignature(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	archivePath := setupSignedDownloadArchive(t, dataRoot, []byte("signed archive"))
	base := downloadCacheEntryBase(t, archivePath)

	cacheKey, err := cacheKeyForPath(archivePath)
	if err != nil {
		t.Fatalf("cacheKeyForPath() error = %v", err)
	}
	entry, err := readDownloadCacheEntry(cacheKey)
	if err != nil {
		t.Fatalf("readDownloadCacheEntry() error = %v", err)
	}

	sig, ok := entry["Sig"].([]byte)
	if !ok || len(sig) == 0 {
		t.Fatalf("entry Sig = %#v, want non-empty []byte", entry["Sig"])
	}
	forged := append([]byte(nil), sig...)
	forged[len(forged)-1] ^= 0xFF
	if err := registry.Put(forged, base+"/Sig"); err != nil {
		t.Fatalf("Put(Sig) error = %v", err)
	}

	err = verifyDownloadArchiveCache(dataRoot, archivePath)
	if err == nil {
		t.Fatal("verifyDownloadArchiveCache() error = nil, want invalid signature")
	}
	if !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("verifyDownloadArchiveCache() error = %v, want signature invalid", err)
	}
}

func TestVerifyDownloadArchiveCacheRejectsMissingSignature(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	archivePath := setupSignedDownloadArchive(t, dataRoot, []byte("signed archive"))
	base := downloadCacheEntryBase(t, archivePath)

	if err := registry.Put([]byte{}, base+"/Sig"); err != nil {
		t.Fatalf("Put(empty Sig) error = %v", err)
	}

	err := verifyDownloadArchiveCache(dataRoot, archivePath)
	if err == nil {
		t.Fatal("verifyDownloadArchiveCache() error = nil, want missing signature")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("verifyDownloadArchiveCache() error = %v, want signature failure", err)
	}
}

func TestSignDownloadArchiveCacheUpdatesAfterContentChange(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	archivePath := setupSignedDownloadArchive(t, dataRoot, []byte("original archive bytes"))

	if err := os.WriteFile(archivePath, []byte("updated archive bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile(updated) error = %v", err)
	}
	if err := signDownloadArchiveCache(dataRoot, archivePath); err != nil {
		t.Fatalf("signDownloadArchiveCache(updated) error = %v", err)
	}
	if err := verifyDownloadArchiveCache(dataRoot, archivePath); err != nil {
		t.Fatalf("verifyDownloadArchiveCache(updated) error = %v", err)
	}
}

func TestVerifyDownloadArchiveCacheCaseInsensitivePath(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	archivePath := setupSignedDownloadArchive(t, dataRoot, []byte("case path archive"))

	upperPath := strings.ToUpper(archivePath)
	if err := verifyDownloadArchiveCache(dataRoot, upperPath); err != nil {
		t.Fatalf("verifyDownloadArchiveCache(upper path) error = %v", err)
	}
}

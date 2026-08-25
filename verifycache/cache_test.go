//go:build windows

package verifycache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	prefs "common/preferences"
	"common/settings"
)

func setupVerifyCacheTestProfile(t *testing.T) string {
	t.Helper()

	dataRoot := t.TempDir()
	installRoot := filepath.Join(dataRoot, "installs")
	if err := os.MkdirAll(installRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll(installRoot) error = %v", err)
	}

	key := `HKCU/Software/NVMTest/verifycache/` + strings.ReplaceAll(t.Name(), "/", "_")
	prefs.ROOT = key
	prefs.ROOTS = []string{key}
	_ = ClearAllCache()
	settings.Load(true)

	if err := settings.Put("root", installRoot); err != nil {
		t.Fatalf("Put(root) error = %v", err)
	}
	settings.Load(true)

	return dataRoot
}

func signedNodeExecutable(t *testing.T) string {
	t.Helper()

	if override := strings.TrimSpace(os.Getenv("NVM_TEST_SIGNED_NODE")); override != "" {
		if _, statErr := os.Stat(override); statErr == nil {
			return override
		}
		t.Fatalf("NVM_TEST_SIGNED_NODE=%q is not accessible", override)
	}

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		t.Skip("LOCALAPPDATA is not set")
	}

	matches, err := filepath.Glob(filepath.Join(localAppData, "Author Software", "nvm", "installs", "*", "node.exe"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	for _, candidate := range matches {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	t.Skip("no signed node.exe found; set NVM_TEST_SIGNED_NODE to run this test")
	return ""
}

func TestSignNodeCacheCreatesRegistryEntry(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	nodePath := signedNodeExecutable(t)

	installDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(installDir) error = %v", err)
	}
	linkPath := filepath.Join(installDir, "node.exe")

	sourceData, err := os.ReadFile(nodePath)
	if err != nil {
		t.Fatalf("ReadFile(source node) error = %v", err)
	}
	if err := os.WriteFile(linkPath, sourceData, 0o755); err != nil {
		t.Fatalf("WriteFile(link node) error = %v", err)
	}

	if err := SignNodeCacheWithSigners(linkPath, []string{"OpenJS Foundation", "Node.js Foundation", "Author Software Inc."}); err != nil {
		t.Fatalf("SignNodeCacheWithSigners() error = %v", err)
	}

	cacheKey, err := cacheKeyForPath(linkPath)
	if err != nil {
		t.Fatalf("cacheKeyForPath() error = %v", err)
	}

	entry, err := readCacheEntry(cacheKey)
	if err != nil {
		t.Fatalf("readCacheEntry() error = %v", err)
	}
	if entry["Path"] == nil || entry["Digest"] == nil || entry["FileID"] == nil || entry["USN"] == nil || entry["Sig"] == nil {
		t.Fatalf("readCacheEntry() = %#v, want content and file-state values", entry)
	}

	if err := verifyStoredSignature(dataRoot, cacheKey, entry); err != nil {
		t.Fatalf("verifyStoredSignature() error = %v", err)
	}
}

func TestClearNodeCacheRemovesEntry(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	nodePath := signedNodeExecutable(t)

	installDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(installDir) error = %v", err)
	}
	linkPath := filepath.Join(installDir, "node.exe")

	sourceData, err := os.ReadFile(nodePath)
	if err != nil {
		t.Fatalf("ReadFile(source node) error = %v", err)
	}
	if err := os.WriteFile(linkPath, sourceData, 0o755); err != nil {
		t.Fatalf("WriteFile(link node) error = %v", err)
	}

	if err := SignNodeCacheWithSigners(linkPath, []string{"OpenJS Foundation", "Node.js Foundation", "Author Software Inc."}); err != nil {
		t.Fatalf("SignNodeCacheWithSigners() error = %v", err)
	}

	if err := ClearNodeCache(linkPath); err != nil {
		t.Fatalf("ClearNodeCache() error = %v", err)
	}

	cacheKey, err := cacheKeyForPath(linkPath)
	if err != nil {
		t.Fatalf("cacheKeyForPath() error = %v", err)
	}
	entry, err := readCacheEntry(cacheKey)
	if err != nil {
		t.Fatalf("readCacheEntry() error = %v", err)
	}
	if len(entry) != 0 {
		t.Fatalf("readCacheEntry() after clear = %#v, want empty", entry)
	}
}

func TestCanonicalPayloadRegression(t *testing.T) {
	state := fileSecurityState{VolumeSerial: 42, FileID: 123, USN: 456}
	payload, err := canonicalPayload(`C:\nvm\installs\v22\node.exe`, 12345, 9876543210, "ABCD1234", "AABBCCDD", state)
	if err != nil {
		t.Fatalf("canonicalPayload() error = %v", err)
	}
	want := "v3\nc:\\nvm\\installs\\v22\\node.exe\n12345\n9876543210\nABCD1234\naabbccdd\n42\n123\n456"
	if payload != want {
		t.Fatalf("canonicalPayload() = %q, want %q", payload, want)
	}
}

func TestNodeFileSecurityStateChangesAfterWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.exe")
	if err := os.WriteFile(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("WriteFile(first): %v", err)
	}
	first, err := nodeFileSecurityState(path)
	if err != nil {
		t.Skipf("USN state unavailable: %v", err)
	}
	if err := os.WriteFile(path, []byte("other"), 0o644); err != nil {
		t.Fatalf("WriteFile(other): %v", err)
	}
	second, err := nodeFileSecurityState(path)
	if err != nil {
		t.Fatalf("nodeFileSecurityState(other): %v", err)
	}
	if first.FileID == second.FileID && first.USN == second.USN {
		t.Fatal("file identity and USN unchanged after content replacement")
	}
}

func BenchmarkNodeFileSecurityState(b *testing.B) {
	path := filepath.Join(b.TempDir(), "node.exe")
	if err := os.WriteFile(path, []byte("benchmark"), 0o644); err != nil {
		b.Fatal(err)
	}
	if _, err := nodeFileSecurityState(path); err != nil {
		b.Skipf("USN state unavailable: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := nodeFileSecurityState(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileSHA256NodeExe(b *testing.B) {
	nodePath := benchSignedNodePath(b)
	if _, err := fileSHA256(nodePath); err != nil {
		b.Fatalf("warmup: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fileSHA256(nodePath); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignNodeCache(b *testing.B) {
	nodePath := benchSignedNodePath(b)
	allowed := []string{"OpenJS Foundation", "Node.js Foundation", "Author Software Inc."}
	if err := SignNodeCacheWithSigners(nodePath, allowed); err != nil {
		b.Fatalf("warmup: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := SignNodeCacheWithSigners(nodePath, allowed); err != nil {
			b.Fatal(err)
		}
	}
}

func benchSignedNodePath(b *testing.B) string {
	b.Helper()
	if override := strings.TrimSpace(os.Getenv("NVM_TEST_SIGNED_NODE")); override != "" {
		if _, err := os.Stat(override); err == nil {
			return override
		}
		b.Fatalf("NVM_TEST_SIGNED_NODE=%q is not accessible", override)
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		b.Skip("LOCALAPPDATA is not set")
	}
	matches, err := filepath.Glob(filepath.Join(localAppData, "Author Software", "nvm", "installs", "*", "node.exe"))
	if err != nil {
		b.Fatalf("Glob: %v", err)
	}
	for _, candidate := range matches {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	b.Skip("no signed node.exe; set NVM_TEST_SIGNED_NODE")
	return ""
}

func TestFileSHA256ChangesWithContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.exe")
	if err := os.WriteFile(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("WriteFile(first): %v", err)
	}
	first, err := fileSHA256(path)
	if err != nil {
		t.Fatalf("fileSHA256(first): %v", err)
	}
	if err := os.WriteFile(path, []byte("other"), 0o644); err != nil {
		t.Fatalf("WriteFile(other): %v", err)
	}
	second, err := fileSHA256(path)
	if err != nil {
		t.Fatalf("fileSHA256(other): %v", err)
	}
	if first == second {
		t.Fatal("fileSHA256() unchanged after same-size content replacement")
	}
}

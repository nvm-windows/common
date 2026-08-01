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
	if entry["Path"] == nil || entry["Sig"] == nil {
		t.Fatalf("readCacheEntry() = %#v, want Path and Sig values", entry)
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
	payload, err := canonicalPayload(`C:\nvm\installs\v22\node.exe`, 12345, 9876543210, "ABCD1234")
	if err != nil {
		t.Fatalf("canonicalPayload() error = %v", err)
	}
	want := "v1\nc:\\nvm\\installs\\v22\\node.exe\n12345\n9876543210\nABCD1234"
	if payload != want {
		t.Fatalf("canonicalPayload() = %q, want %q", payload, want)
	}
}

//go:build windows

package verifycache

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectStatusMissingPubKey(t *testing.T) {
	dataRoot := t.TempDir()

	status, err := CollectStatus(dataRoot)
	if err != nil {
		t.Fatalf("CollectStatus() error = %v", err)
	}
	if status.PubKeyPresent {
		t.Fatal("CollectStatus() PubKeyPresent = true, want false")
	}
	if !status.Degraded {
		t.Fatal("CollectStatus() Degraded = false, want true")
	}
}

func TestCollectStatusAfterSignNodeCache(t *testing.T) {
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

	status, err := CollectStatus(dataRoot)
	if err != nil {
		t.Fatalf("CollectStatus() error = %v", err)
	}
	if !status.PubKeyPresent {
		t.Fatal("CollectStatus() PubKeyPresent = false, want true")
	}
	if status.CacheEntryCount != 1 {
		t.Fatalf("CollectStatus() CacheEntryCount = %d, want 1", status.CacheEntryCount)
	}
	if len(status.CachedPaths) != 1 || status.CachedPaths[0] != linkPath {
		t.Fatalf("CollectStatus() CachedPaths = %#v, want %q", status.CachedPaths, linkPath)
	}
	if status.Degraded {
		t.Fatal("CollectStatus() Degraded = true, want false")
	}
}

func TestRepairForDoctorRestoresMissingPubKey(t *testing.T) {
	dataRoot := t.TempDir()
	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey() error = %v", err)
	}
	if err := os.Remove(PubKeyPath(dataRoot)); err != nil {
		t.Fatalf("Remove(pubkey) error = %v", err)
	}

	if err := RepairForDoctor(dataRoot); err != nil {
		t.Fatalf("RepairForDoctor() error = %v", err)
	}
	if _, err := os.Stat(PubKeyPath(dataRoot)); err != nil {
		t.Fatalf("Stat(repaired pubkey) error = %v", err)
	}
}

func TestWriteDoctorReportDegraded(t *testing.T) {
	var buf bytes.Buffer
	WriteDoctorReport(&buf, Status{
		PubKeyPath:  `C:\nvm\.verify\pubkey.cer`,
		Degraded:    true,
		CachedPaths: nil,
	})

	out := buf.String()
	if !strings.Contains(out, "missing") {
		t.Fatalf("WriteDoctorReport() = %q, want missing pubkey line", out)
	}
	if !strings.Contains(out, "degraded") {
		t.Fatalf("WriteDoctorReport() = %q, want degraded mode line", out)
	}
}

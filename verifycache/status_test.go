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
	if !strings.Contains(out, "Verify key : missing") {
		t.Fatalf("WriteDoctorReport() = %q, want missing verify key", out)
	}
	if !strings.Contains(out, "may lock this key store") || !strings.Contains(out, "Event code: NVM4312") {
		t.Fatalf("WriteDoctorReport() = %q, want NVM4312 antivirus note", out)
	}
}

func TestWriteDoctorReportOpenVerifyKeyOmitsNote(t *testing.T) {
	var buf bytes.Buffer
	WriteDoctorReport(&buf, Status{
		PubKeyPath:    `C:\nvm\.verify\pubkey.cer`,
		PubKeyPresent: true,
		VerifyKeyName: defaultKeyName,
		VerifyKeyOpen: true,
	})
	out := buf.String()
	if strings.Contains(out, "Verify key") || strings.Contains(out, "NVM4312") {
		t.Fatalf("WriteDoctorReport() = %q, want no missing-key note", out)
	}
}

func TestCollectStatusMissingVerifyKey(t *testing.T) {
	prev := openPersistedKeyAttempt
	openPersistedKeyAttempt = func(string) (verifyKey, persistedKeyAttempt, error) {
		return verifyKey{}, persistedKeyAttempt{Provider: msSoftwareKeyProvider, Status: 0x80090016}, errVerifyKeyNotOpen
	}
	t.Cleanup(func() { openPersistedKeyAttempt = prev })

	status, err := CollectStatus(t.TempDir())
	if err != nil {
		t.Fatalf("CollectStatus() error = %v", err)
	}
	if status.VerifyKeyOpen {
		t.Fatal("CollectStatus() VerifyKeyOpen = true, want false")
	}
	if status.VerifyKeyName != defaultKeyName {
		t.Fatalf("CollectStatus() VerifyKeyName = %q", status.VerifyKeyName)
	}
}

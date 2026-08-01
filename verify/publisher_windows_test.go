//go:build windows

package verify

import (
	"os"
	"path/filepath"
	"testing"
)

func signedSyncExecutable(t *testing.T) string {
	t.Helper()

	if override := os.Getenv("NVM_TEST_SIGNED_SYNC"); override != "" {
		if _, err := os.Stat(override); err == nil {
			return override
		}
		t.Fatalf("NVM_TEST_SIGNED_SYNC=%q is not accessible", override)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable() error = %v", err)
	}
	if SignerThumbprint(exe) != "" {
		return exe
	}

	t.Skip("unsigned sync executable; set NVM_TEST_SIGNED_SYNC to run publisher tests")
	return ""
}

func TestVerifySamePublisherAsExecutable(t *testing.T) {
	syncExe := signedSyncExecutable(t)
	if err := VerifyAuthenticode(syncExe); err != nil {
		t.Fatalf("VerifyAuthenticode(sync) error = %v", err)
	}

	if err := VerifySamePublisherAs(syncExe, syncExe); err != nil {
		t.Fatalf("VerifySamePublisherAs(self) error = %v", err)
	}

	unsigned := filepath.Join(t.TempDir(), "unsigned.dll")
	if err := os.WriteFile(unsigned, []byte("not signed"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := VerifySamePublisherAsExecutable(unsigned); err == nil {
		t.Fatal("VerifySamePublisherAsExecutable(unsigned) error = nil, want failure")
	}
}

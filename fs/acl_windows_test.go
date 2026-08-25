//go:build windows

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsDriveRootChild(t *testing.T) {
	tests := map[string]bool{
		`C:\nvm`:                        true,
		`C:\nvm\installs`:               false,
		`D:\nodejs`:                     true,
		`D:\nodejs\installs`:            false,
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Author Software", "nvm"): false,
	}
	for path, want := range tests {
		if got := isDriveRootChild(path); got != want {
			t.Errorf("isDriveRootChild(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsUnderSafeManagedRoot(t *testing.T) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		t.Skip("LOCALAPPDATA not set")
	}

	path := filepath.Join(localAppData, "Author Software", "nvm", "installs")
	if !isUnderSafeManagedRoot(path) {
		t.Fatalf("expected %q to be under a safe managed root", path)
	}
	if isUnderSafeManagedRoot(`C:\nvm`) {
		t.Fatalf("expected C:\\nvm to be risky")
	}
	pd := os.Getenv("ProgramData")
	if pd != "" && isUnderSafeManagedRoot(filepath.Join(pd, "nvm", "installs")) {
		t.Fatalf("ProgramData must not be treated as a safe managed root")
	}
}

func TestIsRiskyManagedPath_NestedUnderDriveRootChild(t *testing.T) {
	if !IsRiskyManagedPath(`C:\nvm\installs`) {
		t.Fatal("expected C:\\nvm\\installs to be risky")
	}
}

func TestHasRiskyDataRootLayout(t *testing.T) {
	if !HasRiskyDataRootLayout(`C:\nvm`) {
		t.Fatal("expected install root on drive root to be flagged")
	}
	if HasRiskyDataRootLayout(filepath.Join(os.Getenv("LOCALAPPDATA"), "Author Software", "nvm", "installs")) {
		t.Fatal("expected default LocalAppData layout to be safe")
	}
}

func TestHardenManagedDirectory_SkipsSafeProfilePath(t *testing.T) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		t.Skip("LOCALAPPDATA not set")
	}

	dir := filepath.Join(localAppData, "nvm-acl-test-safe")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	defer os.RemoveAll(dir)

	if IsRiskyManagedPath(dir) {
		t.Fatalf("expected %q to be skipped", dir)
	}
	if err := HardenManagedDirectory(dir); err != nil {
		t.Fatalf("HardenManagedDirectory: %v", err)
	}
}

func TestHardenManagedDirectory_RiskyPathRejectsCrossUserWrite(t *testing.T) {
	// Use a temp path under a synthetic drive-root-child name when possible.
	// On CI, C:\ may not be writable; skip if create fails.
	dir := `C:\nvm-acl-harden-test`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot create risky test dir: %v", err)
	}
	defer os.RemoveAll(dir)

	if !IsRiskyManagedPath(dir) {
		t.Fatalf("expected %q risky", dir)
	}
	if err := HardenManagedDirectory(dir); err != nil {
		t.Fatalf("HardenManagedDirectory: %v", err)
	}
	if AllowsCrossUserWrite(dir) {
		t.Fatal("expected hardened dir to deny cross-user write")
	}
}

func TestAllowsCrossUserWrite_AuthUsersReadExecuteNotWrite(t *testing.T) {
	dir := `C:\nvm-acl-rx-test`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot create test dir: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := HardenManagedDirectory(dir); err != nil {
		t.Fatalf("harden: %v", err)
	}
	if AllowsCrossUserWrite(dir) {
		t.Fatal("AuthUsers RX must not count as cross-user write")
	}
}


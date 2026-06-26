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

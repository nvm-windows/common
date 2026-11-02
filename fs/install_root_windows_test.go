//go:build windows

package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCheckInstallRootAllowedDefaultOK(t *testing.T) {
	local := mustKnownFolder(t, windows.FOLDERID_LocalAppData, "LOCALAPPDATA")
	path := filepath.Join(local, "Author Software", "nvm", "installs")
	if err := CheckInstallRootAllowed(path); err != nil {
		t.Fatalf("default installs path %q: %v", path, err)
	}
	if !IsSafeToDeleteInstallRoot(path) {
		t.Fatalf("default installs path should be removable")
	}
}

func TestCheckInstallRootAllowedTempChildOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvm-versions")
	if err := CheckInstallRootAllowed(path); err != nil {
		t.Fatalf("temp child %q: %v", path, err)
	}
}

func TestCheckInstallRootAllowedDedicatedOK(t *testing.T) {
	docs := mustKnownFolder(t, windows.FOLDERID_Documents)
	path := filepath.Join(docs, "nvm-versions")
	if err := CheckInstallRootAllowed(path); err != nil {
		t.Fatalf("documents child %q: %v", path, err)
	}
}

func TestCheckInstallRootAllowedRejectsProtected(t *testing.T) {
	local := mustKnownFolder(t, windows.FOLDERID_LocalAppData, "LOCALAPPDATA")
	profile := mustKnownFolder(t, windows.FOLDERID_Profile, "USERPROFILE")
	pf := mustKnownFolder(t, windows.FOLDERID_ProgramFiles, "ProgramFiles")
	win := mustKnownFolder(t, windows.FOLDERID_Windows, "SystemRoot")
	docs := mustKnownFolder(t, windows.FOLDERID_Documents)

	cases := []string{
		pf,
		filepath.Join(pf, "nodejs"),
		win,
		filepath.Join(win, "System32"),
		profile,
		filepath.Dir(profile),
		local,
		docs,
		filepath.Join(local, "Author Software", "nvm"),
		filepath.Join(local, "Author Software"),
		filepath.Join(local, "Programs"),
		filepath.Join(local, "Microsoft"),
		`C:\`,
		`C:\nvm`,
		`D:\soft`,
		``,
		`\\server\share\nvm`,
	}
	for _, path := range cases {
		t.Run(emptyName(path), func(t *testing.T) {
			err := CheckInstallRootAllowed(path)
			if err == nil {
				t.Fatalf("CheckInstallRootAllowed(%q) = nil, want NVM4313", path)
			}
			if !strings.Contains(err.Error(), InstallRootDeniedEvent) {
				t.Fatalf("error %q missing %s", err, InstallRootDeniedEvent)
			}
			if path != "" && IsSafeToDeleteInstallRoot(path) {
				t.Fatalf("IsSafeToDeleteInstallRoot(%q) = true, want false", path)
			}
		})
	}
}

func TestCheckInstallRootAllowedNestedUnderDriveOK(t *testing.T) {
	// D:\tools\nvm\installs — parent is not a drive root, so DataRoot stays off the drive.
	path := `C:\nvm-tools\installs`
	if err := CheckInstallRootAllowed(path); err != nil {
		t.Fatalf("nested path %q: %v", path, err)
	}
}

func TestCheckInstallRootAllowedRejectsForeignContents(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckInstallRootAllowed(root); err == nil {
		t.Fatalf("expected NVM4313 for directory with foreign child")
	}
	if IsSafeToDeleteInstallRoot(root) {
		t.Fatal("foreign contents must not be DelTree-safe")
	}
}

func TestCheckInstallRootAllowedAllowsVersionTreesOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "v22.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "v24.11.1-rc.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckInstallRootAllowed(root); err != nil {
		t.Fatalf("version-only root: %v", err)
	}
	if !IsSafeToDeleteInstallRoot(root) {
		t.Fatal("version-only root should be DelTree-safe")
	}
}

func TestIsSafeToDeleteInstallRootRejectsMixedContents(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "v22.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "IntelliJ IDEA"), 0o755); err != nil {
		t.Fatal(err)
	}
	if IsSafeToDeleteInstallRoot(root) {
		t.Fatal("mixed NVM + foreign contents must not be DelTree-safe")
	}
}

func TestInstallRootDeniedMessageListsEvent(t *testing.T) {
	msg := InstallRootDeniedMessage()
	if !strings.Contains(msg, "Event code: NVM4313") {
		t.Fatalf("message missing event code: %s", msg)
	}
	if !strings.Contains(msg, "Program Files") {
		t.Fatalf("message missing Program Files list")
	}
	if !strings.Contains(msg, "directly under a drive root") {
		t.Fatalf("message missing drive-root-child guidance: %s", msg)
	}
}

func mustKnownFolder(t *testing.T, id *windows.KNOWNFOLDERID, envNames ...string) string {
	t.Helper()
	path := knownFolder(id, envNames...)
	if path == "" {
		t.Skip("known folder unavailable")
	}
	return path
}

func emptyName(path string) string {
	if path == "" {
		return "empty"
	}
	return path
}

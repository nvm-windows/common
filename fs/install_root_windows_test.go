//go:build windows

package fs

import (
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

func TestInstallRootDeniedMessageListsEvent(t *testing.T) {
	msg := InstallRootDeniedMessage()
	if !strings.Contains(msg, "Event code: NVM4313") {
		t.Fatalf("message missing event code: %s", msg)
	}
	if !strings.Contains(msg, "Program Files") {
		t.Fatalf("message missing Program Files list")
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

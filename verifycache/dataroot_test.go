//go:build windows

package verifycache

import (
	"common/settings"
	"path/filepath"
	"testing"
)

func TestDataRootFromSettingsUsesLocalAppDataNotInstallParent(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)

	// Point InstallRoot at a custom tree; DataRoot must stay under LOCALAPPDATA.
	customInstall := filepath.Join(t.TempDir(), "D", "nvm", "installs")
	if err := settings.Put("root", customInstall); err != nil {
		t.Fatalf("Put(root) error = %v", err)
	}
	settings.Load(true)

	got, err := dataRootFromSettings()
	if err != nil {
		t.Fatalf("dataRootFromSettings() error = %v", err)
	}
	if got != dataRoot {
		t.Fatalf("dataRootFromSettings() = %q, want %q", got, dataRoot)
	}
	if got == filepath.Dir(customInstall) {
		t.Fatal("dataRootFromSettings must not return parent(InstallRoot)")
	}
}

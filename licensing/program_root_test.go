package license

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheckCommunityProgramRootUnderLocalAppData(t *testing.T) {
	base := t.TempDir()
	withLocalAppData(t, base)
	withCommunityLayoutEdition(t, true)

	prefix := filepath.Join(base, CommunityOrgLabel, CommunityAlias)
	for _, root := range []string{prefix, filepath.Join(prefix, "utils")} {
		got := CheckCommunityProgramRoot(root)
		if !got.OK {
			t.Fatalf("CheckCommunityProgramRoot(%q) OK=false message=%q", root, got.Message)
		}
		if got.SkippedCommercial {
			t.Fatalf("unexpected SkippedCommercial for community path")
		}
		if got.ExpectedPrefix != filepath.Clean(prefix) {
			t.Fatalf("ExpectedPrefix=%q want %q", got.ExpectedPrefix, prefix)
		}
	}
}

func TestCheckCommunityProgramRootOutsideLocalAppData(t *testing.T) {
	base := t.TempDir()
	withLocalAppData(t, base)
	withCommunityLayoutEdition(t, true)

	outside := filepath.Join(t.TempDir(), "tools", "nvm")
	got := CheckCommunityProgramRoot(outside)
	if got.OK {
		t.Fatalf("expected warn for %q", outside)
	}
	for _, part := range []string{LayoutWarnCode, "Certified Builds", outside} {
		if !strings.Contains(got.Message, part) {
			t.Fatalf("message missing %q: %q", part, got.Message)
		}
	}
}

func TestCheckCommunityProgramRootProgramFiles(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Program Files path check is Windows-oriented")
	}
	base := t.TempDir()
	withLocalAppData(t, base)
	withCommunityLayoutEdition(t, true)

	pf := `C:\Program Files\Author Software\nvm`
	got := CheckCommunityProgramRoot(pf)
	if got.OK {
		t.Fatalf("expected warn for Program Files layout")
	}
	for _, part := range []string{LayoutWarnCode, "Certified Builds"} {
		if !strings.Contains(got.Message, part) {
			t.Fatalf("message missing %q: %q", part, got.Message)
		}
	}
}

func TestCheckCommunityProgramRootSkipsCommercial(t *testing.T) {
	base := t.TempDir()
	withLocalAppData(t, base)
	withCommunityLayoutEdition(t, false)

	outside := filepath.Join(t.TempDir(), "anywhere")
	got := CheckCommunityProgramRoot(outside)
	if !got.OK || !got.SkippedCommercial {
		t.Fatalf("got OK=%v SkippedCommercial=%v want skip commercial", got.OK, got.SkippedCommercial)
	}
	if got.Message != "" {
		t.Fatalf("commercial skip should not set message, got %q", got.Message)
	}
}

func TestPathUnderPrefix(t *testing.T) {
	prefix := filepath.Join("C:", "Users", "a", "AppData", "Local", "Author Software", "nvm")
	child := filepath.Join(prefix, "utils")
	sibling := filepath.Join("C:", "Users", "a", "AppData", "Local", "Other", "nvm")
	if !pathUnderPrefix(prefix, prefix) {
		t.Fatal("prefix should contain itself")
	}
	if !pathUnderPrefix(child, prefix) {
		t.Fatal("child should be under prefix")
	}
	if pathUnderPrefix(sibling, prefix) {
		t.Fatal("sibling must not match")
	}
	if pathUnderPrefix(filepath.Join(prefix, "..", "other"), prefix) {
		t.Fatal("escaped relative path must not match")
	}
}

func withLocalAppData(t *testing.T, dir string) {
	t.Helper()
	orig := localAppDataDir
	localAppDataDir = func() (string, error) { return filepath.Clean(dir), nil }
	t.Cleanup(func() { localAppDataDir = orig })
}

func withCommunityLayoutEdition(t *testing.T, community bool) {
	t.Helper()
	orig := isCommunityEditionForLayout
	isCommunityEditionForLayout = func() bool { return community }
	t.Cleanup(func() { isCommunityEditionForLayout = orig })
}

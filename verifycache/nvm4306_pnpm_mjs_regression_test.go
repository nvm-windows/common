//go:build windows

package verifycache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Regression for NVM4306: proxy resolvePackageModuleEntry prefers
// node_modules/pnpm/bin/pnpm.mjs over the top-level pnpm.cmd wrapper.
// Signing only the .cmd left the launched .mjs without a script-trust
// entry, so ensureDelegatedScriptTrusted rejected the run.
//
// Keep PackageManagerCliRelPathsFor("pnpm") ordered like shim
// pnpm_module_rel_paths (mjs → cjs → js).

func TestPackageManagerCliRelPathsCoverProxyPnpmPreference(t *testing.T) {
	want := []string{
		"node_modules/pnpm/bin/pnpm.mjs",
		"node_modules/pnpm/bin/pnpm.cjs",
		"node_modules/pnpm/bin/pnpm.js",
	}
	got := PackageManagerCliRelPathsFor("pnpm")
	if len(got) != len(want) {
		t.Fatalf("PackageManagerCliRelPathsFor(pnpm) = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("PackageManagerCliRelPathsFor(pnpm)[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	all := map[string]struct{}{}
	for _, rel := range packageManagerCliRelPaths() {
		all[rel] = struct{}{}
	}
	for _, rel := range want {
		if _, ok := all[rel]; !ok {
			t.Fatalf("packageManagerCliRelPaths() missing proxy-preferred %q", rel)
		}
	}
}

func TestSignVersionScriptsTrustsProxyPreferredPnpmMjs(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	pnpmBin := filepath.Join(versionDir, "node_modules", "pnpm", "bin")
	if err := os.MkdirAll(pnpmBin, 0o755); err != nil {
		t.Fatalf("MkdirAll(pnpmBin): %v", err)
	}

	cmdPath := filepath.Join(versionDir, "pnpm.cmd")
	mjsPath := filepath.Join(pnpmBin, "pnpm.mjs")
	cmdBody := "@ECHO off\r\n\"%_prog%\" \"%dp0%\\node_modules\\pnpm\\bin\\pnpm.mjs\" %*\r\n"
	if err := os.WriteFile(cmdPath, []byte(cmdBody), 0o644); err != nil {
		t.Fatalf("WriteFile(pnpm.cmd): %v", err)
	}
	if err := os.WriteFile(mjsPath, []byte("export {}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(pnpm.mjs): %v", err)
	}

	// Pre-fix world: only the wrapper is signed → launched .mjs is a miss.
	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey: %v", err)
	}
	if err := signDelegatedScript(dataRoot, cmdPath, true); err != nil {
		t.Fatalf("signDelegatedScript(pnpm.cmd): %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, cmdPath); err != nil {
		t.Fatalf("verifyDelegatedScript(pnpm.cmd): %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, mjsPath); !errors.Is(err, ErrScriptCacheMiss) {
		t.Fatalf("verifyDelegatedScript(pnpm.mjs) before SignVersionScripts = %v, want ErrScriptCacheMiss", err)
	}
	if !IsDelegatedLauncherPath(mjsPath) {
		t.Fatal("IsDelegatedLauncherPath(pnpm.mjs) must be true so --sign-script can repair")
	}

	if err := signVersionScripts(dataRoot, versionDir); err != nil {
		t.Fatalf("signVersionScripts(): %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, mjsPath); err != nil {
		t.Fatalf("verifyDelegatedScript(pnpm.mjs) after SignVersionScripts: %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, cmdPath); err != nil {
		t.Fatalf("verifyDelegatedScript(pnpm.cmd) after SignVersionScripts: %v", err)
	}
}

func TestIsDelegatedLauncherPathAcceptsPnpmMjsUnderInstalls(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	mjsPath := filepath.Join(versionDir, "node_modules", "pnpm", "bin", "pnpm.mjs")
	if !IsDelegatedLauncherPath(mjsPath) {
		t.Fatal("pnpm.mjs under installs must be a delegated launcher path")
	}

	// Non-install .mjs must still be refused by the path gate.
	evil := filepath.Join(t.TempDir(), "evil.mjs")
	if IsDelegatedLauncherPath(evil) {
		t.Fatalf("temp .mjs must not be delegated: %s", evil)
	}
}

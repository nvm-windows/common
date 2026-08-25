//go:build windows

package verifycache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVersionScriptsSignsPackageManagerCliEntrypoints(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	cliDir := filepath.Join(versionDir, "node_modules", "npm", "bin")
	if err := os.MkdirAll(cliDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(cliDir): %v", err)
	}

	cliPath := filepath.Join(cliDir, "npm-cli.js")
	if err := os.WriteFile(cliPath, []byte("console.log('npm')\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(npm-cli.js): %v", err)
	}

	if err := signVersionScripts(dataRoot, versionDir); err != nil {
		t.Fatalf("signVersionScripts(): %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, cliPath); err != nil {
		t.Fatalf("verifyDelegatedScript(npm-cli.js): %v", err)
	}
}

func TestVerifyDelegatedScriptRejectsPlantedScript(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(versionDir): %v", err)
	}

	trusted := filepath.Join(versionDir, "npm.cmd")
	if err := os.WriteFile(trusted, []byte("@ECHO OFF\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(npm.cmd): %v", err)
	}
	if err := signVersionScripts(dataRoot, versionDir); err != nil {
		t.Fatalf("signVersionScripts(): %v", err)
	}

	planted := filepath.Join(versionDir, "evil.cmd")
	if err := os.WriteFile(planted, []byte("@ECHO OFF\r\necho planted\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(evil.cmd): %v", err)
	}

	err := verifyDelegatedScript(dataRoot, planted)
	if !errors.Is(err, ErrScriptCacheMiss) {
		t.Fatalf("verifyDelegatedScript(planted) = %v, want ErrScriptCacheMiss", err)
	}
}

func TestVerifyDelegatedScriptRejectsTamperedScript(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(versionDir): %v", err)
	}

	scriptPath := filepath.Join(versionDir, "npm.cmd")
	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(npm.cmd): %v", err)
	}
	if err := signVersionScripts(dataRoot, versionDir); err != nil {
		t.Fatalf("signVersionScripts(): %v", err)
	}

	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\necho tampered\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(tampered): %v", err)
	}

	if err := verifyDelegatedScript(dataRoot, scriptPath); err == nil {
		t.Fatal("verifyDelegatedScript() = nil, want tamper rejection")
	}
}

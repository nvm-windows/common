//go:build windows

package verifycache

import (
	"os"
	"path/filepath"
	"testing"

	"common/settings"
)

func TestSignDelegatedScriptSkipsUntrustedDiskChange(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey: %v", err)
	}
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	scriptPath := filepath.Join(versionDir, "opencode.cmd")
	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("initial sign: %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, scriptPath); err != nil {
		t.Fatalf("initial verify: %v", err)
	}

	if err := settings.Put("untrusted_module_handler_action", "deny"); err != nil {
		t.Fatalf("Put deny: %v", err)
	}
	settings.Load(true)

	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\necho changed\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile changed: %v", err)
	}
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("resign untrusted: %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, scriptPath); err == nil {
		t.Fatal("verify after untrusted change = nil, want stale cache rejection")
	}
}

func TestSignDelegatedScriptResignsTrustedDiskChange(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey: %v", err)
	}
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	scriptPath := filepath.Join(versionDir, "opencode.cmd")
	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("initial sign: %v", err)
	}

	if err := settings.Put("trusted_modules", "NOT ALL,opencode"); err != nil {
		t.Fatalf("Put trusted: %v", err)
	}
	if err := settings.Put("untrusted_module_handler_action", "deny"); err != nil {
		t.Fatalf("Put deny: %v", err)
	}
	settings.Load(true)

	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\necho trusted-change\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile changed: %v", err)
	}
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("resign trusted: %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, scriptPath); err != nil {
		t.Fatalf("verify after trusted resign: %v", err)
	}
}

func TestSignDelegatedScriptIgnoresSignChangedEnv(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey: %v", err)
	}
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	scriptPath := filepath.Join(versionDir, "opencode.cmd")
	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("initial sign: %v", err)
	}

	if err := settings.Put("untrusted_module_handler_action", "deny"); err != nil {
		t.Fatalf("Put deny: %v", err)
	}
	settings.Load(true)

	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\necho pm-install\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile changed: %v", err)
	}
	t.Setenv("NVM_SIGN_CHANGED_MODULES", "1")
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("resign with env: %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, scriptPath); err == nil {
		t.Fatal("verify after spoofed env resign = nil, want stale cache rejection")
	}
}

func TestSignDelegatedScriptResignsWhenAllowSignChanged(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey: %v", err)
	}
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	scriptPath := filepath.Join(versionDir, "opencode.cmd")
	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("initial sign: %v", err)
	}

	if err := settings.Put("untrusted_module_handler_action", "deny"); err != nil {
		t.Fatalf("Put deny: %v", err)
	}
	settings.Load(true)

	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\necho pm-install\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile changed: %v", err)
	}
	SetAllowSignChanged(true)
	t.Cleanup(func() { SetAllowSignChanged(false) })
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("resign with allowSignChanged: %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, scriptPath); err != nil {
		t.Fatalf("verify after authorized resign: %v", err)
	}
}

func TestSignDelegatedScriptResignsWhenHandlerAllow(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey: %v", err)
	}
	versionDir := filepath.Join(dataRoot, "installs", "v22.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	scriptPath := filepath.Join(versionDir, "opencode.cmd")
	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("initial sign: %v", err)
	}

	if err := settings.Put("untrusted_module_handler_action", "allow"); err != nil {
		t.Fatalf("Put allow: %v", err)
	}
	settings.Load(true)

	if err := os.WriteFile(scriptPath, []byte("@ECHO OFF\r\necho allow-change\r\n"), 0o644); err != nil {
		t.Fatalf("WriteFile changed: %v", err)
	}
	if err := signDelegatedScript(dataRoot, scriptPath, false); err != nil {
		t.Fatalf("resign allow: %v", err)
	}
	if err := verifyDelegatedScript(dataRoot, scriptPath); err != nil {
		t.Fatalf("verify after allow resign: %v", err)
	}
}

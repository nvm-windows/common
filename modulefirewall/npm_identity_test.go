package modulefirewall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNpmCredentialPresentAndFingerprint(t *testing.T) {
	m := map[string]any{
		"registry":                         "https://registry.npmjs.org",
		"//registry.npmjs.org/:_authToken": "npm_secrettoken",
	}
	if !npmCredentialPresent(m) {
		t.Fatal("want credential present")
	}
	key, fp := npmCredentialFingerprint(m)
	if key == "" || fp == "" {
		t.Fatal("want fingerprint")
	}
	m2 := map[string]any{"//registry.npmjs.org/:_authToken": "npm_secrettoken"}
	_, fp2 := npmCredentialFingerprint(m2)
	if fp2 != fp {
		t.Fatal("fingerprint should be stable for same key+token")
	}
	if npmCredentialPresent(map[string]any{"registry": "https://registry.npmjs.org"}) {
		t.Fatal("want no credential")
	}
}

func TestIdentityForCredentialHostIgnoresForeignUsername(t *testing.T) {
	m := map[string]any{
		"//registry.npmjs.org/:_authToken": "npm_real",
		"//evil.example/:username":         "alice",
	}
	name, _, _ := identityForCredentialHost(m, "//registry.npmjs.org/:_authToken")
	if name != "" {
		t.Fatalf("want empty name, got %q", name)
	}
	m["//registry.npmjs.org/:username"] = "corey"
	name, _, src := identityForCredentialHost(m, "//registry.npmjs.org/:_authToken")
	if name != "corey" || src != "npmrc-login" {
		t.Fatalf("got name=%q src=%q", name, src)
	}
}

func TestRefreshNpmIdentityCachesUsernameAcrossSameToken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LOCALAPPDATA", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", filepath.Join(dir, "AppData", "Roaming"))

	cwd := t.TempDir()
	token := "npm_testtoken_abc"
	content := "//registry.npmjs.org/:_authToken=" + token + "\n//registry.npmjs.org/:username=alice\n"
	if err := os.WriteFile(filepath.Join(cwd, ".npmrc"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := RefreshNpmIdentity(cwd, "", "")
	if !snap.Authenticated || snap.Name != "alice" {
		t.Fatalf("snap=%#v", snap)
	}

	// Drop username from npmrc but keep same token — cache should retain name.
	content2 := "//registry.npmjs.org/:_authToken=" + token + "\n"
	if err := os.WriteFile(filepath.Join(cwd, ".npmrc"), []byte(content2), 0o600); err != nil {
		t.Fatal(err)
	}
	snap2 := RefreshNpmIdentity(cwd, "", "")
	if !snap2.Authenticated || snap2.Name != "alice" {
		t.Fatalf("want cached alice, got %#v", snap2)
	}
	if snap2.Source != "npm-identity-cache" {
		t.Fatalf("source=%q", snap2.Source)
	}

	// Logout clears
	if err := os.WriteFile(filepath.Join(cwd, ".npmrc"), []byte("registry=https://registry.npmjs.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap3 := RefreshNpmIdentity(cwd, "", "")
	if snap3.Authenticated || snap3.Name != "" {
		t.Fatalf("want cleared, got %#v", snap3)
	}
}

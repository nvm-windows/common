package modulefirewall

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestNpmProfileFromConfig(t *testing.T) {
	cfg := map[string]any{
		"email":            "dev@example.com",
		"init-author-name": "Dev",
		"registry":         "https://registry.npmjs.org",
		"//registry.npmjs.org/:_authToken": "secret",
	}
	scrubAuthKeys(cfg)
	if _, ok := cfg["//registry.npmjs.org/:_authToken"]; ok {
		t.Fatal("auth token should be scrubbed")
	}
	prof := npmProfileFromConfig(cfg)
	m, ok := prof.(map[string]any)
	if !ok {
		t.Fatalf("profile=%#v", prof)
	}
	if m["email"] != "dev@example.com" || m["name"] != "Dev" {
		t.Fatalf("%#v", m)
	}
	if m["source"] != "npmrc" {
		t.Fatalf("source=%v", m["source"])
	}
}

func TestNpmProfileRegistryOnlyYieldsNil(t *testing.T) {
	t.Setenv("USERNAME", "corey")
	prof := npmProfileFromConfig(map[string]any{
		"registry": "https://registry.npmjs.org",
	})
	if prof != nil {
		t.Fatalf("want nil profile for registry-only npmrc, got %#v", prof)
	}
}

func TestNpmLoginIdentityUsername(t *testing.T) {
	prof := npmLoginIdentityFromNpmrc(map[string]any{
		"//registry.npmjs.org/:username": "alice",
		"registry":                       "https://registry.npmjs.org",
	})
	m, ok := prof.(map[string]any)
	if !ok {
		t.Fatalf("profile=%#v", prof)
	}
	if m["name"] != "alice" || m["source"] != "npmrc-login" {
		t.Fatalf("%#v", m)
	}
}

func TestNpmLoginIdentityBasicAuth(t *testing.T) {
	prof := npmLoginIdentityFromNpmrc(map[string]any{
		"_auth": "dXNlcjpwYXNz",
	})
	m, ok := prof.(map[string]any)
	if !ok {
		t.Fatalf("profile=%#v", prof)
	}
	if m["name"] != "user" || m["source"] != "npmrc-login" {
		t.Fatalf("%#v", m)
	}
}

func TestNpmLoginIdentityJWT(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"name":"jwt-user","email":"j@e.c"}`))
	token := "eyJhbGciOiJub25lIn0." + payload + ".sig"
	prof := npmLoginIdentityFromNpmrc(map[string]any{
		"//registry.npmjs.org/:_authToken": token,
	})
	m, ok := prof.(map[string]any)
	if !ok {
		t.Fatalf("profile=%#v", prof)
	}
	if m["name"] != "jwt-user" || m["email"] != "j@e.c" || m["source"] != "npmrc-login" {
		t.Fatalf("%#v", m)
	}
	if npmLoginIdentityFromNpmrc(map[string]any{"_authToken": "npm_secrettoken"}) != nil {
		t.Fatal("want nil for npm_ prefix token")
	}
}

func TestBuildRequestContextReadsNpmrc(t *testing.T) {
	iso := t.TempDir()
	t.Setenv("LOCALAPPDATA", iso)
	t.Setenv("USERPROFILE", iso)
	t.Setenv("HOME", iso)
	t.Setenv("APPDATA", filepath.Join(iso, "AppData", "Roaming"))

	dir := t.TempDir()
	npmrc := "email=a@b.c\ninit-author-name=Tester\nregistry=https://registry.npmjs.org\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrc), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := BuildRequestContext(dir, "npm", "22.0.0")
	if ctx.Config == nil {
		t.Fatal("want npm config")
	}
	// Author fields alone are not the npm login user.
	if ctx.User != "" {
		t.Fatalf("want empty user without credential username, got %q", ctx.User)
	}
	if ctx.PMFamily != "npm" {
		t.Fatalf("family=%q", ctx.PMFamily)
	}
	key, pm := ctx.PackageManagerClaim()
	if key != "npm" || pm["config"] == nil {
		t.Fatalf("claim=%q %#v", key, pm)
	}
	if pm["user"] != nil {
		t.Fatalf("user=%v want null", pm["user"])
	}
}

func TestBuildRequestContextUsernameOnlyNpmrc(t *testing.T) {
	iso := t.TempDir()
	t.Setenv("LOCALAPPDATA", iso)
	t.Setenv("USERPROFILE", iso)
	t.Setenv("HOME", iso)
	t.Setenv("APPDATA", filepath.Join(iso, "AppData", "Roaming"))

	dir := t.TempDir()
	npmrc := "//registry.npmjs.org/:username=alice\nregistry=https://registry.npmjs.org\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrc), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := BuildRequestContext(dir, "npm", "22.0.0")
	if ctx.Authenticated {
		t.Fatal("username-only npmrc must not set authenticated")
	}
	if ctx.User != "" {
		t.Fatalf("want empty user without host credential, got %q", ctx.User)
	}
}

func TestBuildRequestContextHostScopedUsername(t *testing.T) {
	iso := t.TempDir()
	t.Setenv("LOCALAPPDATA", iso)
	t.Setenv("USERPROFILE", iso)
	t.Setenv("HOME", iso)
	t.Setenv("APPDATA", filepath.Join(iso, "AppData", "Roaming"))

	dir := t.TempDir()
	npmrc := "//registry.npmjs.org/:_authToken=npm_x\n//registry.npmjs.org/:username=corey\n//evil.example/:username=alice\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrc), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := BuildRequestContext(dir, "npm", "22.0.0")
	if !ctx.Authenticated {
		t.Fatal("want authenticated")
	}
	if ctx.User != "corey" {
		t.Fatalf("want corey, got %q", ctx.User)
	}
	_, pm := ctx.PackageManagerClaim()
	if pm["user"] != "corey" || pm["authenticated"] != true {
		t.Fatalf("%#v", pm)
	}
}

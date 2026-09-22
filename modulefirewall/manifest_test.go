package modulefirewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePackageJSONDirectDeps(t *testing.T) {
	raw := []byte(`{
  "dependencies": {"lodash": "^4.17.21", "@scope/pkg": "1.0.0"},
  "devDependencies": {"eslint": "8.0.0"},
  "optionalDependencies": {"fsevents": "2.3.2"}
}`)
	pkgs, err := ParsePackageJSONDirectDeps(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("want 4 pkgs, got %d %#v", len(pkgs), pkgs)
	}
	pkgs, err = ParsePackageJSONDirectDeps(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("want 3 without dev, got %d", len(pkgs))
	}
}

func TestParseLockPackages(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	content := `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/@scope/pkg": {"version": "1.2.3", "name": "@scope/pkg"}
  }
}`
	if err := os.WriteFile(lock, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := ParseLockPackages(lock)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 pkgs (skip root), got %d %#v", len(pkgs), pkgs)
	}
}

func TestBuildManifestArtifact_LockPreferred(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"a":"1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/a": {"version": "1.0.0"},
    "node_modules/b": {"version": "2.0.0"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	art, err := BuildManifestArtifact(CollectOptions{Cwd: dir, Command: "npm", Args: []string{"install"}, SkipLockfile: false})
	if err != nil {
		t.Fatal(err)
	}
	if art.Source != "lock" {
		t.Fatalf("source=%s", art.Source)
	}
	if art.PackageShasum != "" {
		t.Fatalf("lock path must not set package shasum")
	}
	if !strings.Contains(string(art.Body), "a@") && !strings.Contains(string(art.Body), "a\n") {
		// body is newline module lines
		if len(art.Modules) < 2 {
			t.Fatalf("want lock modules, got %#v body=%q", art.Modules, art.Body)
		}
	}

	art, err = BuildManifestArtifact(CollectOptions{Cwd: dir, Command: "npm", Args: []string{"install"}, SkipLockfile: true})
	if err != nil {
		t.Fatal(err)
	}
	if art.Source != "package.json" {
		t.Fatalf("skip lock want package.json, got %s", art.Source)
	}
	if art.PackageShasum == "" {
		t.Fatal("want x-nvm-package-shasum source")
	}
	if !strings.Contains(string(art.Body), `"dependencies"`) {
		t.Fatalf("body should be package.json bytes")
	}
}

func TestProductionOmit(t *testing.T) {
	if !productionOmit([]string{"install", "--production"}) {
		t.Fatal("want omit")
	}
	if !productionOmit([]string{"install", "--omit=dev"}) {
		t.Fatal("want omit")
	}
	if productionOmit([]string{"install"}) {
		t.Fatal("want include dev")
	}
}

func TestCapHumanStrings(t *testing.T) {
	items := make([]string, 25)
	for i := range items {
		items[i] = "x"
	}
	got := CapHumanStrings(items)
	if len(got) != 21 {
		t.Fatalf("len=%d", len(got))
	}
	if got[20] != "and 5 more" {
		t.Fatalf("tail=%q", got[20])
	}
}

func TestManifestExpandable(t *testing.T) {
	if !ManifestExpandable("npm", []string{"ci"}) {
		t.Fatal("npm ci")
	}
	if ManifestExpandable("npx", []string{"eslint"}) {
		t.Fatal("npx should not expand")
	}
	if ManifestExpandable("npm", []string{"exec", "eslint"}) {
		t.Fatal("exec should not expand")
	}
}

func TestFirewallUserAgent(t *testing.T) {
	if got := FirewallUserAgent("2.0.1", "certified"); got != "NVM for Windows/2.0.1 certified" {
		t.Fatalf("got %q", got)
	}
	if got := FirewallUserAgent("v2.0.1", "Community"); got != "NVM for Windows/2.0.1 community" {
		t.Fatalf("got %q", got)
	}
}

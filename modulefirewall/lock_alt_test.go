package modulefirewall

import (
	"strings"
	"testing"
)

func TestParsePnpmLockContent(t *testing.T) {
	content := `lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-x}
  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-y}
`
	pkgs, err := parsePnpmLockContent(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d %#v", len(pkgs), pkgs)
	}
	names := map[string]string{}
	for _, p := range pkgs {
		names[p.Name] = p.Version
	}
	if names["lodash"] != "4.17.21" || names["@scope/pkg"] != "1.2.3" {
		t.Fatalf("%#v", names)
	}
}

func TestParseYarnLockContentClassic(t *testing.T) {
	content := `# yarn lockfile v1
lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
`
	pkgs, err := parseYarnLockContent(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "lodash" || pkgs[0].Version != "4.17.21" {
		t.Fatalf("%#v", pkgs)
	}
}

func TestParseYarnLockContentBerry(t *testing.T) {
	content := `"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`
	pkgs, err := parseYarnLockContent(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "lodash" {
		t.Fatalf("%#v", pkgs)
	}
}

func TestLockfileCandidates(t *testing.T) {
	pnpm := LockfileCandidates("pnpm")
	if pnpm[0] != "pnpm-lock.yaml" {
		t.Fatalf("%v", pnpm)
	}
	yarn := LockfileCandidates("yarn")
	if yarn[0] != "yarn.lock" {
		t.Fatalf("%v", yarn)
	}
	npm := LockfileCandidates("npm")
	if !strings.HasPrefix(npm[0], "package-lock") {
		t.Fatalf("%v", npm)
	}
}

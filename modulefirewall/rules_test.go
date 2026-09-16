package modulefirewall

import "testing"

func TestIsPackageAllowed_NotAllWithException(t *testing.T) {
	rules := []string{"NOT ALL", "porthog"}
	pkg, _ := ParsePackageToken("porthog")
	ok, err := IsPackageAllowed(pkg, rules)
	if err != nil || !ok {
		t.Fatalf("porthog allowed=%v err=%v", ok, err)
	}
	pkg2, _ := ParsePackageToken("eslint")
	ok, err = IsPackageAllowed(pkg2, rules)
	if err != nil || ok {
		t.Fatalf("eslint should deny, got allowed=%v err=%v", ok, err)
	}
}

func TestIsPackageAllowed_DefaultAll(t *testing.T) {
	pkg, _ := ParsePackageToken("anything")
	ok, err := IsPackageAllowed(pkg, nil)
	if err != nil || !ok {
		t.Fatalf("empty list should default ALL, allowed=%v err=%v", ok, err)
	}
}

func TestIsPackageAllowed_OrgWildcard(t *testing.T) {
	rules := []string{"NOT ALL", "@org/*"}
	pkg, _ := ParsePackageToken("@org/pkg@1.2.3")
	ok, err := IsPackageAllowed(pkg, rules)
	if err != nil || !ok {
		t.Fatalf("@org/pkg allowed=%v err=%v", ok, err)
	}
}

func TestIsPackageAllowed_VersionRange(t *testing.T) {
	rules := []string{"eslint@>=8.0.0"}
	pkg, _ := ParsePackageToken("eslint@8.1.0")
	ok, err := IsPackageAllowed(pkg, rules)
	if err != nil || !ok {
		t.Fatalf("eslint@8.1 allowed=%v err=%v", ok, err)
	}
	pkg2, _ := ParsePackageToken("eslint@7.0.0")
	ok, err = IsPackageAllowed(pkg2, rules)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		// exclusive list with only eslint@>=8 — 7.0 should deny
		t.Fatal("eslint@7 should be denied by exclusive allow list")
	}
}

func TestExtractPackageArgs_npmGlobal(t *testing.T) {
	args := []string{"install", "-g", "porthog@", "left-pad"}
	// fix - use valid
	args = []string{"install", "-g", "porthog", "left-pad"}
	if !InstallLike("npm", args) || !IsGlobalInstall("npm", args) {
		t.Fatal("expected global install")
	}
	pkgs := ExtractPackageArgs("npm", args)
	if len(pkgs) != 2 {
		t.Fatalf("pkgs=%v", pkgs)
	}
}

func TestExtractHTTPSURL(t *testing.T) {
	u, ok := ExtractHTTPSURL([]string{"https://policy.example/fw"})
	if !ok || u == "" {
		t.Fatal("expected https url")
	}
	_, ok = ExtractHTTPSURL([]string{"eslint", "ALL"})
	if ok {
		t.Fatal("local rules should not be URL mode")
	}
}

package modulefirewall

import (
	"strings"
	"testing"
)

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

func TestNormalizeList(t *testing.T) {
	tests := []struct {
		name  string
		in    []string
		seed  string
		want  []string
		isNil bool
	}{
		{"strip blanks", []string{"", "  ", "eslint", "\t"}, "ALL", []string{"eslint"}, false},
		{"empty to seed", nil, "ALL", []string{"ALL"}, false},
		{"empty to NOT ALL seed", []string{"", "  "}, "NOT ALL", []string{"NOT ALL"}, false},
		{"empty seed yields nil", nil, "", nil, true},
		{"empty seed blanks nil", []string{"", " "}, "  ", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeList(tt.in, tt.seed)
			if tt.isNil {
				if got != nil {
					t.Fatalf("got %#v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("got %#v, want %#v", got, tt.want)
				}
			}
		})
	}
}

func TestValidateRuleEntry(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		wantErr bool
		errSub  string
	}{
		{"ALL", "ALL", false, ""},
		{"bang eslint", "!eslint", false, ""},
		{"NOT ALL", "NOT ALL", false, ""},
		{"org wildcard", "@org/*", false, ""},
		{"bad org wildcard", "org/*", true, "invalid org wildcard"},
		{"http reject", "http://evil.example/fw", true, "HTTPS"},
		{"https ok", "https://policy.example/fw", false, ""},
		{"star pin", "name@1.*", false, ""},
		{"range pin", "name@>=1.0.0", false, ""},
		{"empty err", "", true, "empty"},
		{"bang alone err", "!", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleEntry(tt.entry)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Fatalf("err=%v, want substring %q", err, tt.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err=%v", err)
			}
		})
	}
}

func TestParsePackageToken(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    PackageSpec
		wantErr bool
	}{
		{
			name: "scoped version",
			raw:  "@a/b@1.2.3",
			want: PackageSpec{Name: "@a/b", Version: "1.2.3", Raw: "@a/b@1.2.3"},
		},
		{
			name: "unscoped version",
			raw:  "a@1",
			want: PackageSpec{Name: "a", Version: "1", Raw: "a@1"},
		},
		{
			name: "git plus raw",
			raw:  "git+https://example.com/repo.git",
			want: PackageSpec{Name: "git+https://example.com/repo.git", Raw: "git+https://example.com/repo.git"},
		},
		{
			name: "file colon raw",
			raw:  "file:/path/to/pkg",
			want: PackageSpec{Name: "file:/path/to/pkg", Raw: "file:/path/to/pkg"},
		},
		{
			name: "path raw",
			raw:  "./local/pkg",
			want: PackageSpec{Name: "./local/pkg", Raw: "./local/pkg"},
		},
		{name: "empty err", raw: "", wantErr: true},
		{name: "blank err", raw: "   ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePackageToken(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err=%v", err)
			}
			if got != tt.want {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestIsPackageAllowed_Extras(t *testing.T) {
	tests := []struct {
		name    string
		pkg     string
		rules   []string
		wantOK  bool
		wantErr string
	}{
		{"bang deny", "eslint", []string{"ALL", "!eslint"}, false, ""},
		{"exclusive miss deny", "lodash", []string{"eslint"}, false, ""},
		{"ALL allow", "anything", []string{"ALL"}, true, ""},
		{"NOT ALL alone deny", "eslint", []string{"NOT ALL"}, false, ""},
		{"star pin match", "name@1.2.3", []string{"name@1.*"}, true, ""},
		{"star pin miss", "name@2.0.0", []string{"name@1.*"}, false, ""},
		{"https forces remote", "eslint", []string{"https://policy.example/fw"}, false, "EvaluateRemote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, err := ParsePackageToken(tt.pkg)
			if err != nil {
				t.Fatal(err)
			}
			ok, err := IsPackageAllowed(pkg, tt.rules)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err=%v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("allowed=%v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestFilterBlocked(t *testing.T) {
	rules := []string{"NOT ALL", "eslint", "porthog"}
	pkgs := []PackageSpec{}
	for _, raw := range []string{"eslint", "lodash", "porthog", "left-pad"} {
		p, err := ParsePackageToken(raw)
		if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	blocked, err := FilterBlocked(pkgs, rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 2 {
		t.Fatalf("blocked=%v, want lodash + left-pad", blocked)
	}
	names := map[string]bool{}
	for _, b := range blocked {
		names[b.Name] = true
	}
	if !names["lodash"] || !names["left-pad"] {
		t.Fatalf("blocked names=%v", names)
	}
}

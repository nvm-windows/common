package resolver

import (
	"strings"
	"testing"
)

func TestResolveInstalledVersion_ResolvePartialRemotely(t *testing.T) {
	originalCheckInstalledLocally := checkInstalledLocallyFn
	originalLatestInstalledMatch := latestInstalledMatchFn
	originalFindVersion := findVersionFn
	originalIsInstalled := isInstalledFn
	defer func() {
		checkInstalledLocallyFn = originalCheckInstalledLocally
		latestInstalledMatchFn = originalLatestInstalledMatch
		findVersionFn = originalFindVersion
		isInstalledFn = originalIsInstalled
	}()

	latestInstalledMatchFn = func(spec string, installed ...[]string) (string, bool) {
		t.Fatalf("latestInstalledMatchFn should not be used for remote partial resolution")
		return "", false
	}
	checkInstalledLocallyFn = func(spec string) (string, bool) {
		if spec != "22.9.0" {
			t.Fatalf("checkInstalledLocallyFn called with %q, want %q", spec, "22.9.0")
		}
		return "", false
	}
	findVersionFn = func(spec string) (string, string, error) {
		if spec != "22" {
			t.Fatalf("findVersionFn called with %q, want %q", spec, "22")
		}
		return "22.9.0", "10.0.0", nil
	}
	isInstalledFn = func(spec string) (bool, string, error) {
		t.Fatalf("isInstalledFn should not be used for remote partial resolution")
		return false, "", nil
	}

	installed, version, err := ResolveInstalledVersion("22", true)
	if err != nil {
		t.Fatalf("ResolveInstalledVersion returned error: %v", err)
	}
	if installed {
		t.Fatalf("installed = true, want false")
	}
	if version != "22.9.0" {
		t.Fatalf("version = %q, want %q", version, "22.9.0")
	}
}

func TestResolveInstalledVersion_LocalPartialOnly(t *testing.T) {
	originalCheckInstalledLocally := checkInstalledLocallyFn
	originalLatestInstalledMatch := latestInstalledMatchFn
	originalFindVersion := findVersionFn
	originalIsInstalled := isInstalledFn
	defer func() {
		checkInstalledLocallyFn = originalCheckInstalledLocally
		latestInstalledMatchFn = originalLatestInstalledMatch
		findVersionFn = originalFindVersion
		isInstalledFn = originalIsInstalled
	}()

	latestInstalledMatchFn = func(spec string, installed ...[]string) (string, bool) {
		if spec != "22" {
			t.Fatalf("latestInstalledMatchFn called with %q, want %q", spec, "22")
		}
		return "22.1.0", true
	}
	checkInstalledLocallyFn = func(spec string) (string, bool) {
		return "", false
	}
	findVersionFn = func(spec string) (string, string, error) {
		t.Fatalf("findVersionFn should not be used when partials are local-only")
		return "", "", nil
	}
	isInstalledFn = func(spec string) (bool, string, error) {
		t.Fatalf("isInstalledFn should not be used when a local partial match exists")
		return false, "", nil
	}

	installed, version, err := ResolveInstalledVersion("22", false)
	if err != nil {
		t.Fatalf("ResolveInstalledVersion returned error: %v", err)
	}
	if !installed {
		t.Fatalf("installed = false, want true")
	}
	if version != "22.1.0" {
		t.Fatalf("version = %q, want %q", version, "22.1.0")
	}
}

func TestResolveInstalledVersion_UserAliasSkipsCatalog(t *testing.T) {
	originalCheckInstalledLocally := checkInstalledLocallyFn
	originalLatestInstalledMatch := latestInstalledMatchFn
	originalFindVersion := findVersionFn
	originalIsInstalled := isInstalledFn
	originalResolveLocal := resolveLocalOnlyAliasFn
	defer func() {
		checkInstalledLocallyFn = originalCheckInstalledLocally
		latestInstalledMatchFn = originalLatestInstalledMatch
		findVersionFn = originalFindVersion
		isInstalledFn = originalIsInstalled
		resolveLocalOnlyAliasFn = originalResolveLocal
	}()

	resolveLocalOnlyAliasFn = func(spec string) (string, bool) {
		if strings.EqualFold(spec, "legacy") {
			return "20.20.2", true
		}
		return "", false
	}
	findVersionFn = func(spec string) (string, string, error) {
		t.Fatalf("findVersionFn should not run for local user alias, got %q", spec)
		return "", "", nil
	}
	latestInstalledMatchFn = func(spec string, installed ...[]string) (string, bool) {
		return "", false
	}
	checkInstalledLocallyFn = func(spec string) (string, bool) {
		if NormalizeVersion(spec) == "20.20.2" {
			return "20.20.2", true
		}
		return "", false
	}
	isInstalledFn = func(spec string) (bool, string, error) {
		t.Fatalf("isInstalledFn should not run, got %q", spec)
		return false, "", nil
	}

	installed, version, err := ResolveInstalledVersion("legacy", false)
	if err != nil {
		t.Fatalf("ResolveInstalledVersion: %v", err)
	}
	if !installed {
		t.Fatal("expected installed=true")
	}
	if version != "20.20.2" {
		t.Fatalf("version=%q want 20.20.2", version)
	}
}

func TestResolveInstalledVersion_NamedSpecifierResolvesWhenLocalOnly(t *testing.T) {
	originalCheckInstalledLocally := checkInstalledLocallyFn
	originalLatestInstalledMatch := latestInstalledMatchFn
	originalFindVersion := findVersionFn
	originalIsInstalled := isInstalledFn
	defer func() {
		checkInstalledLocallyFn = originalCheckInstalledLocally
		latestInstalledMatchFn = originalLatestInstalledMatch
		findVersionFn = originalFindVersion
		isInstalledFn = originalIsInstalled
	}()

	latestInstalledMatchFn = func(spec string, installed ...[]string) (string, bool) {
		return "", false
	}
	checkInstalledLocallyFn = func(spec string) (string, bool) {
		return "", false
	}
	findVersionFn = func(spec string) (string, string, error) {
		if spec != "lts" {
			t.Fatalf("findVersionFn called with %q, want %q", spec, "lts")
		}
		return "22.17.0", "10.0.0", nil
	}
	isInstalledFn = func(spec string) (bool, string, error) {
		t.Fatalf("isInstalledFn should not be used for named specifiers")
		return false, "", nil
	}

	installed, version, err := ResolveInstalledVersion("lts", false)
	if err != nil {
		t.Fatalf("ResolveInstalledVersion returned error: %v", err)
	}
	if installed {
		t.Fatalf("installed = true, want false")
	}
	if version != "22.17.0" {
		t.Fatalf("version = %q, want %q", version, "22.17.0")
	}
}

func TestResolveInstalledVersion_MissingLocalPartialDoesNotResolveRemotely(t *testing.T) {
	originalCheckInstalledLocally := checkInstalledLocallyFn
	originalLatestInstalledMatch := latestInstalledMatchFn
	originalFindVersion := findVersionFn
	originalIsInstalled := isInstalledFn
	defer func() {
		checkInstalledLocallyFn = originalCheckInstalledLocally
		latestInstalledMatchFn = originalLatestInstalledMatch
		findVersionFn = originalFindVersion
		isInstalledFn = originalIsInstalled
	}()

	latestInstalledMatchFn = func(spec string, installed ...[]string) (string, bool) {
		return "", false
	}
	checkInstalledLocallyFn = func(spec string) (string, bool) {
		return "", false
	}
	findVersionFn = func(spec string) (string, string, error) {
		t.Fatalf("findVersionFn should not be used when partials are local-only")
		return "", "", nil
	}
	isInstalledFn = func(spec string) (bool, string, error) {
		t.Fatalf("isInstalledFn should not be used for a missing local-only partial")
		return false, "", nil
	}

	installed, version, err := ResolveInstalledVersion("22", false)
	if err != nil {
		t.Fatalf("ResolveInstalledVersion returned error: %v", err)
	}
	if installed {
		t.Fatalf("installed = true, want false")
	}
	if version != "22" {
		t.Fatalf("version = %q, want %q", version, "22")
	}
}

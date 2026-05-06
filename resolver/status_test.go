package resolver

import "testing"

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
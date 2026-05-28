package settings_test

import (
	"common/registry"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	prefs "common/preferences"
	"common/settings"
)

const testRegistryRoot = "HKCU/Software/NVMTest/settings_test"
const testPolicyRegistryRoot = "HKCU/Software/NVMTest/Policies/settings_test"

func TestMain(m *testing.M) {
	prefs.ROOT = testRegistryRoot
	prefs.ROOTS = []string{prefs.ROOT}
	code := m.Run()
	// Best-effort cleanup: remove the entire NVMTest hive used by these tests.
	exec.Command("reg", "delete", `HKCU\Software\NVMTest`, "/f").Run() //nolint:errcheck
	os.Exit(code)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func mustPut(t *testing.T, name, value string) {
	t.Helper()
	if err := settings.Put(name, value); err != nil {
		t.Fatalf("Put(%q, %q) unexpected error: %v", name, value, err)
	}
}

func mustGet(t *testing.T, name string) interface{} {
	t.Helper()
	v, err := settings.Get(name)
	if err != nil {
		t.Fatalf("Get(%q) unexpected error: %v", name, err)
	}
	return v
}

func wantPutError(t *testing.T, name, value string) {
	t.Helper()
	if err := settings.Put(name, value); err == nil {
		t.Errorf("Put(%q, %q) expected error, got nil", name, value)
	}
}

func withPolicyRoot(t *testing.T) {
	t.Helper()

	oldRoot := prefs.ROOT
	oldRoots := append([]string(nil), prefs.ROOTS...)
	prefs.ROOT = testRegistryRoot
	prefs.ROOTS = []string{testPolicyRegistryRoot, prefs.ROOT}

	t.Cleanup(func() {
		prefs.ROOT = oldRoot
		prefs.ROOTS = oldRoots
	})
}

// ── mode ─────────────────────────────────────────────────────────────────────

func TestMode_Valid(t *testing.T) {
	for _, mode := range []string{"shim", "symlink", "junction"} {
		t.Run(mode, func(t *testing.T) {
			mustPut(t, "mode", mode)
			got := mustGet(t, "mode")
			if got != mode {
				t.Errorf("expected %q, got %v", mode, got)
			}
		})
	}
}

func TestMode_Invalid(t *testing.T) {
	for _, bad := range []string{"", "nvm", "Shim", "SYMLINK", "auto"} {
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			wantPutError(t, "mode", bad)
		})
	}
}

func TestPut_BlockedByPolicy(t *testing.T) {
	withPolicyRoot(t)

	if err := registry.Put("shim", testPolicyRegistryRoot+"/OperatingMode"); err != nil {
		t.Fatalf("seed policy mode: %v", err)
	}

	err := settings.Put("mode", "link")
	if err == nil {
		t.Fatal("expected Put(mode) to fail when policy is present")
	}
	if !strings.Contains(err.Error(), "managed by policy") {
		t.Fatalf("expected managed-by-policy error, got %v", err)
	}

	if got := mustGet(t, "mode"); got != "shim" {
		t.Fatalf("expected effective mode shim, got %v", got)
	}

	if _, exists, err := registry.Get(testRegistryRoot + "/OperatingMode"); err != nil {
		t.Fatalf("read preference mode: %v", err)
	} else if exists {
		t.Fatal("expected no user preference write when policy blocks the setting")
	}
}

func TestDel_BlockedByPolicy(t *testing.T) {
	withPolicyRoot(t)

	if err := registry.Put("shim", testPolicyRegistryRoot+"/OperatingMode"); err != nil {
		t.Fatalf("seed policy mode: %v", err)
	}
	if err := registry.Put("link", testRegistryRoot+"/OperatingMode"); err != nil {
		t.Fatalf("seed user preference mode: %v", err)
	}

	err := settings.Del("mode")
	if err == nil {
		t.Fatal("expected Del(mode) to fail when policy is present")
	}
	if !strings.Contains(err.Error(), "managed by policy") {
		t.Fatalf("expected managed-by-policy error, got %v", err)
	}

	if got := mustGet(t, "mode"); got != "shim" {
		t.Fatalf("expected effective mode shim, got %v", got)
	}

	if value, exists, err := registry.Get(testRegistryRoot + "/OperatingMode"); err != nil {
		t.Fatalf("read user preference mode: %v", err)
	} else if !exists || value != "link" {
		t.Fatalf("expected existing user preference to remain untouched, got exists=%v value=%v", exists, value)
	}
}

// ── root ─────────────────────────────────────────────────────────────────────

func TestRoot_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "nvm_settings_test_root")
	defer os.RemoveAll(dir)

	mustPut(t, "root", dir)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("expected Put(root) to create the directory, but it does not exist")
	}

	got := mustGet(t, "root")
	if got != dir {
		t.Errorf("expected %q, got %v", dir, got)
	}
}

func TestRoot_EmptyRejected(t *testing.T) {
	wantPutError(t, "root", "")
}

func TestRoot_BlankSpaceRejected(t *testing.T) {
	wantPutError(t, "root", "   ")
}

// ── proxy ─────────────────────────────────────────────────────────────────────

func TestProxy_ValidURL(t *testing.T) {
	const proxy = "http://proxy.example.com:8080"
	mustPut(t, "proxy", proxy)
	got := mustGet(t, "proxy")
	if got != proxy {
		t.Errorf("expected %q, got %v", proxy, got)
	}
}

func TestProxy_EmptyAllowed(t *testing.T) {
	// Empty clears the proxy setting — must not error.
	mustPut(t, "proxy", "")
}

func TestProxy_InvalidURL(t *testing.T) {
	for _, bad := range []string{"not-a-url", "://missing-scheme", "relative/path", "just text"} {
		t.Run(bad, func(t *testing.T) {
			wantPutError(t, "proxy", bad)
		})
	}
}

func TestProxyAuth_SingleValue(t *testing.T) {
	const proxyAuth = "builduser:s3cr3t"
	mustPut(t, "proxy_auth", proxyAuth)
	got := mustGet(t, "proxy_auth")
	if got != proxyAuth {
		t.Errorf("expected %q, got %v", proxyAuth, got)
	}
}

func TestProxyAuth_LoadsLegacyMultiStringAsSingleValue(t *testing.T) {
	t.Cleanup(func() {
		_ = settings.Del("proxy_auth")
		settings.Load(true)
	})

	if err := registry.Put([]string{"", "builduser:s3cr3t", "NTLM"}, testRegistryRoot+"/ProxyAuth"); err != nil {
		t.Fatalf("write legacy ProxyAuth multi-string: %v", err)
	}

	settings.Load(true)
	if got := settings.Global().ProxyAuth; got != "builduser:s3cr3t" {
		t.Fatalf("expected legacy ProxyAuth to load first non-empty value, got %q", got)
	}

	got := mustGet(t, "proxy_auth")
	if got != "builduser:s3cr3t" {
		t.Fatalf("expected Get(proxy_auth) to normalize legacy multi-string, got %v", got)
	}
}

// ── node_mirror ───────────────────────────────────────────────────────────────

func TestNodeMirror_ValidURL(t *testing.T) {
	const mirror = "https://nodejs.org/dist"
	mustPut(t, "node_mirror", mirror)

	got := mustGet(t, "node_mirror")
	if !containsURL(got, "nodejs.org") {
		t.Errorf("expected stored mirror to contain %q, got %v", "nodejs.org", got)
	}
}

func TestNodeMirror_MultipleValidURLs(t *testing.T) {
	const mirrors = "https://nodejs.org/dist,https://mirror.example.com/node"
	mustPut(t, "node_mirror", mirrors)

	got := mustGet(t, "node_mirror")
	if !containsURL(got, "nodejs.org") || !containsURL(got, "mirror.example.com") {
		t.Errorf("expected both mirrors to be stored, got %v", got)
	}
}

func TestNodeMirror_InvalidURL(t *testing.T) {
	for _, bad := range []string{"not-a-url", "//no-scheme", "relative"} {
		t.Run(bad, func(t *testing.T) {
			wantPutError(t, "node_mirror", bad)
		})
	}
}

func TestNodeMirror_OneInvalidInList(t *testing.T) {
	wantPutError(t, "node_mirror", "https://valid.example.com,not-a-url")
}

// ── npm_mirror ────────────────────────────────────────────────────────────────

func TestNpmMirror_ValidURL(t *testing.T) {
	const mirror = "https://github.com/npm/cli/archive/"
	mustPut(t, "npm_mirror", mirror)

	got := mustGet(t, "npm_mirror")
	if !containsURL(got, "github.com") {
		t.Errorf("expected stored mirror to contain %q, got %v", "github.com", got)
	}
}

func TestNpmMirror_InvalidURL(t *testing.T) {
	for _, bad := range []string{"not-a-url", "just text", "://"} {
		t.Run(bad, func(t *testing.T) {
			wantPutError(t, "npm_mirror", bad)
		})
	}
}

// ── active_version ────────────────────────────────────────────────────────────

func TestActiveVersion_ValidSemver(t *testing.T) {
	for _, ver := range []string{"22.0.0", "18.12.1", "20.0.0-alpha.1", "16.14.2+build.1", "v22.0.0"} {
		t.Run(ver, func(t *testing.T) {
			mustPut(t, "active_version", ver)
			got := mustGet(t, "active_version")
			if got != ver {
				t.Errorf("expected %q, got %v", ver, got)
			}
		})
	}
}

func TestActiveVersion_EmptyAllowed(t *testing.T) {
	mustPut(t, "active_version", "")
}

func TestActiveVersion_InvalidSemver(t *testing.T) {
	for _, bad := range []string{"22", "22.0", "not-a-version", "1.2.3.4", "abc.def.ghi"} {
		t.Run(bad, func(t *testing.T) {
			wantPutError(t, "active_version", bad)
		})
	}
}

// ── auto_use ──────────────────────────────────────────────────────────────────

func TestAutoUse_ValidValues(t *testing.T) {
	cases := []struct {
		input    string
		expected bool
	}{
		{"0", false},
		{"1", true},
		{"false", false},
		{"true", true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			mustPut(t, "auto_use", tc.input)
			got := mustGet(t, "auto_use")
			if got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestAutoUse_InvalidValues(t *testing.T) {
	for _, bad := range []string{"", "2", "yes", "no", "on", "off"} {
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			wantPutError(t, "auto_use", bad)
		})
	}
}

// ── auto_install ──────────────────────────────────────────────────────────────

func TestAutoInstall_ValidValues(t *testing.T) {
	cases := []struct {
		input    string
		expected bool
	}{
		{"0", false},
		{"1", true},
		{"false", false},
		{"true", true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			mustPut(t, "auto_install", tc.input)
			got := mustGet(t, "auto_install")
			if got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestAutoInstall_InvalidValues(t *testing.T) {
	for _, bad := range []string{"", "2", "yes", "no", "on", "off"} {
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			wantPutError(t, "auto_install", bad)
		})
	}
}

// ── unknown setting ───────────────────────────────────────────────────────────

func TestPut_UnknownSetting(t *testing.T) {
	if err := settings.Put("nonexistent", "value"); err == nil {
		t.Error("expected error for unknown setting, got nil")
	}
}

func TestGet_UnknownSetting(t *testing.T) {
	if _, err := settings.Get("nonexistent"); err == nil {
		t.Error("expected error for unknown setting, got nil")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// containsURL checks whether v (string or []string) contains a substring.
func containsURL(v interface{}, substr string) bool {
	switch val := v.(type) {
	case string:
		return strings.Contains(val, substr)
	case []string:
		for _, s := range val {
			if strings.Contains(s, substr) {
				return true
			}
		}
	}
	return false
}

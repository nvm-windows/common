package settings_test

import (
	prefs "common/preferences"
	"common/settings"
	"os/exec"
	"reflect"
	"testing"
)

const firewallSettingsTestRoot = "HKCU/Software/NVMTest/firewall_settings"

func withFirewallPrefs(t *testing.T) {
	t.Helper()

	oldRoot := prefs.ROOT
	oldRoots := append([]string(nil), prefs.ROOTS...)
	oldUserPref := prefs.USER_PREFERENCE_ROOT
	oldMachinePref := prefs.MACHINE_PREFERENCE_ROOT
	oldSecurityRoots := append([]string(nil), prefs.SECURITY_POLICY_ROOTS...)

	prefs.USER_PREFERENCE_ROOT = firewallSettingsTestRoot + "/user"
	prefs.MACHINE_PREFERENCE_ROOT = firewallSettingsTestRoot + "/machine"
	prefs.ROOT = prefs.USER_PREFERENCE_ROOT
	prefs.ROOTS = []string{prefs.ROOT}
	prefs.SECURITY_POLICY_ROOTS = nil

	t.Cleanup(func() {
		_ = exec.Command("reg", "delete", `HKCU\Software\NVMTest\firewall_settings`, "/f").Run()
		prefs.ROOT = oldRoot
		prefs.ROOTS = oldRoots
		prefs.USER_PREFERENCE_ROOT = oldUserPref
		prefs.MACHINE_PREFERENCE_ROOT = oldMachinePref
		prefs.SECURITY_POLICY_ROOTS = oldSecurityRoots
		settings.Load(true)
	})
}

func TestFirewall_UntrustedModuleHandlerActionDefaultPrompt(t *testing.T) {
	withFirewallPrefs(t)

	got, err := settings.Get("untrusted_module_handler_action")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "prompt" && got != "" {
		def, _ := settings.DefaultValue("untrusted_module_handler_action")
		if def != "prompt" {
			t.Fatalf("got %#v, default %#v, want prompt", got, def)
		}
	}
	if s, ok := got.(string); ok && s != "" && s != "prompt" {
		t.Fatalf("got %q, want prompt/empty", s)
	}
}

func TestFirewall_UntrustedModuleHandlerActionPutGet(t *testing.T) {
	withFirewallPrefs(t)

	if err := settings.Put("untrusted_module_handler_action", "prompt"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := settings.Get("untrusted_module_handler_action")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "prompt" {
		t.Fatalf("got %#v, want prompt", got)
	}

	if err := settings.Put("untrusted_module_handler_action", "allow"); err != nil {
		t.Fatalf("Put allow: %v", err)
	}
	got, err = settings.Get("untrusted_module_handler_action")
	if err != nil {
		t.Fatalf("Get allow: %v", err)
	}
	if got != "allow" {
		t.Fatalf("got %#v, want allow", got)
	}
}

func TestFirewall_TrustedModulesMultiSZ(t *testing.T) {
	withFirewallPrefs(t)

	if err := settings.Put("trusted_modules", "NOT ALL,porthog"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := settings.Get("trusted_modules")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	list, ok := got.([]string)
	if !ok {
		t.Fatalf("got %T %#v, want []string", got, got)
	}
	want := []string{"NOT ALL", "porthog"}
	if !reflect.DeepEqual(list, want) {
		t.Fatalf("got %#v, want %#v", list, want)
	}
}

func TestFirewall_SkipLockfileAndVerboseDefaults(t *testing.T) {
	withFirewallPrefs(t)

	defSkip, err := settings.DefaultValue("firewall_skip_lockfile")
	if err != nil {
		t.Fatalf("DefaultValue skip: %v", err)
	}
	if defSkip != false && defSkip != "false" && defSkip != 0 {
		// bool default from tag
		if b, ok := defSkip.(bool); !ok || b {
			t.Fatalf("firewall_skip_lockfile default=%#v want false", defSkip)
		}
	}

	defVerbose, err := settings.DefaultValue("apply_verbose_firewall_metadata")
	if err != nil {
		t.Fatalf("DefaultValue verbose: %v", err)
	}
	if b, ok := defVerbose.(bool); ok && b {
		t.Fatalf("apply_verbose_firewall_metadata default true, want false")
	}

	cfg := settings.Global()
	if cfg.FirewallSkipLockfile {
		t.Fatal("FirewallSkipLockfile want default false")
	}
	if cfg.ApplyVerboseFirewallMetadata {
		t.Fatal("ApplyVerboseFirewallMetadata want default false")
	}
}

func TestFirewall_ApprovedModulesPutGet(t *testing.T) {
	withFirewallPrefs(t)

	if err := settings.Put("approved_modules", "eslint,@org/*"); err != nil {
		t.Fatalf("Put approved_modules: %v", err)
	}
	if err := settings.Put("approved_global_modules", "ALL"); err != nil {
		t.Fatalf("Put approved_global_modules: %v", err)
	}

	got, err := settings.Get("approved_modules")
	if err != nil {
		t.Fatalf("Get approved_modules: %v", err)
	}
	list, ok := got.([]string)
	if !ok || !reflect.DeepEqual(list, []string{"eslint", "@org/*"}) {
		t.Fatalf("approved_modules=%#v", got)
	}

	got, err = settings.Get("approved_global_modules")
	if err != nil {
		t.Fatalf("Get approved_global_modules: %v", err)
	}
	list, ok = got.([]string)
	if !ok || !reflect.DeepEqual(list, []string{"ALL"}) {
		t.Fatalf("approved_global_modules=%#v", got)
	}
}

func TestFirewall_HTTPTimeoutSeconds(t *testing.T) {
	withFirewallPrefs(t)

	got, err := settings.Get("firewall_http_timeout_seconds")
	if err != nil {
		t.Fatalf("Get default: %v", err)
	}
	switch v := got.(type) {
	case string:
		if v != "3" && v != "" {
			def, _ := settings.DefaultValue("firewall_http_timeout_seconds")
			if def != "3" {
				t.Fatalf("got %#v default %#v, want 3", got, def)
			}
		}
	case int:
		if v != 3 {
			t.Fatalf("got %d, want 3", v)
		}
	case uint32:
		if v != 3 {
			t.Fatalf("got %d, want 3", v)
		}
	default:
		def, _ := settings.DefaultValue("firewall_http_timeout_seconds")
		if def != "3" {
			t.Fatalf("got %#v (%T), default %#v", got, got, def)
		}
	}

	if err := settings.Put("firewall_http_timeout_seconds", "5"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err = settings.Get("firewall_http_timeout_seconds")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	switch v := got.(type) {
	case string:
		if v != "5" {
			t.Fatalf("got %q, want 5", v)
		}
	case int:
		if v != 5 {
			t.Fatalf("got %d, want 5", v)
		}
	case uint32:
		if v != 5 {
			t.Fatalf("got %d, want 5", v)
		}
	default:
		t.Fatalf("got %#v (%T)", got, got)
	}
}

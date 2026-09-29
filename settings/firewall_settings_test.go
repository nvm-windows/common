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
	if s, ok := got.(string); ok && s != "" && s != "prompt" {
		t.Fatalf("got %q, want prompt/empty", s)
	}
	def, _ := settings.DefaultValue("untrusted_module_handler_action")
	if def != "prompt" {
		t.Fatalf("default %#v, want prompt", def)
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

package settings_test

import (
	prefs "common/preferences"
	"common/registry"
	"common/settings"
	"os/exec"
	"reflect"
	"testing"
)

const securityPolicyTestRoot = "HKCU/Software/NVMTest/security_policy"

func TestLoadIgnoresHKCUForSecurityPolicySettings(t *testing.T) {
	oldSecurityRoots := append([]string(nil), prefs.SECURITY_POLICY_ROOTS...)
	oldMachinePolicyRoot := prefs.MACHINE_POLICY_ROOT
	oldUserPolicyRoot := prefs.USER_POLICY_ROOT

	prefs.MACHINE_POLICY_ROOT = securityPolicyTestRoot + "/machine_policy"
	prefs.USER_POLICY_ROOT = securityPolicyTestRoot + "/user_policy"
	prefs.SECURITY_POLICY_ROOTS = []string{prefs.MACHINE_POLICY_ROOT}

	t.Cleanup(func() {
		_ = exec.Command("reg", "delete", `HKCU\Software\NVMTest\security_policy`, "/f").Run()
		prefs.SECURITY_POLICY_ROOTS = oldSecurityRoots
		prefs.MACHINE_POLICY_ROOT = oldMachinePolicyRoot
		prefs.USER_POLICY_ROOT = oldUserPolicyRoot
		settings.Load(true)
	})

	if err := registry.Put([]string{"Evil Signer"}, prefs.USER_POLICY_ROOT+"/AllowedSigners"); err != nil {
		t.Fatalf("registry.Put user policy AllowedSigners: %v", err)
	}
	if err := registry.PutBool(true, prefs.USER_POLICY_ROOT+"/AllowInsecureDownloads"); err != nil {
		t.Fatalf("registry.Put user policy AllowInsecureDownloads: %v", err)
	}

	settings.Load(true)
	cfg := settings.Global()

	if reflect.DeepEqual(cfg.AllowedSigners, []string{"Evil Signer"}) {
		t.Fatalf("AllowedSigners = %#v, HKCU policy must be ignored", cfg.AllowedSigners)
	}
	if cfg.AllowInsecureDownloads {
		t.Fatal("AllowInsecureDownloads = true, HKCU policy must be ignored")
	}
}

func TestLoadUsesHKCUPreferenceForSecurityPolicySettings(t *testing.T) {
	oldSecurityRoots := append([]string(nil), prefs.SECURITY_POLICY_ROOTS...)
	oldMachinePolicyRoot := prefs.MACHINE_POLICY_ROOT
	oldUserPolicyRoot := prefs.USER_POLICY_ROOT
	oldUserPreferenceRoot := prefs.USER_PREFERENCE_ROOT
	oldRoots := append([]string(nil), prefs.ROOTS...)
	oldRoot := prefs.ROOT

	prefs.MACHINE_POLICY_ROOT = securityPolicyTestRoot + "/machine_policy"
	prefs.USER_POLICY_ROOT = securityPolicyTestRoot + "/user_policy"
	prefs.USER_PREFERENCE_ROOT = securityPolicyTestRoot + "/user_preference"
	prefs.ROOT = prefs.USER_PREFERENCE_ROOT
	prefs.SECURITY_POLICY_ROOTS = []string{prefs.MACHINE_POLICY_ROOT}
	prefs.ROOTS = []string{prefs.MACHINE_POLICY_ROOT, prefs.USER_POLICY_ROOT, prefs.USER_PREFERENCE_ROOT}

	t.Cleanup(func() {
		_ = exec.Command("reg", "delete", `HKCU\Software\NVMTest\security_policy`, "/f").Run()
		prefs.SECURITY_POLICY_ROOTS = oldSecurityRoots
		prefs.MACHINE_POLICY_ROOT = oldMachinePolicyRoot
		prefs.USER_POLICY_ROOT = oldUserPolicyRoot
		prefs.USER_PREFERENCE_ROOT = oldUserPreferenceRoot
		prefs.ROOTS = oldRoots
		prefs.ROOT = oldRoot
		settings.Load(true)
	})

	if err := registry.PutBool(true, prefs.USER_PREFERENCE_ROOT+"/AllowInsecureDownloads"); err != nil {
		t.Fatalf("registry.Put user preference AllowInsecureDownloads: %v", err)
	}

	settings.Load(true)
	if !settings.Global().AllowInsecureDownloads {
		t.Fatal("AllowInsecureDownloads = false, want true from HKCU preference fallback")
	}

	got, err := settings.Get("allow_insecure_downloads")
	if err != nil {
		t.Fatalf("Get(allow_insecure_downloads) error = %v", err)
	}
	if value, ok := got.(bool); !ok || !value {
		t.Fatalf("Get(allow_insecure_downloads) = %#v, want true", got)
	}
}

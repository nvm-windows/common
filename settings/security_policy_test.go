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

func TestLoadAirGappedFromHKLMPolicyOnly(t *testing.T) {
	oldSecurityRoots := append([]string(nil), prefs.SECURITY_POLICY_ROOTS...)
	oldMachinePolicyRoot := prefs.MACHINE_POLICY_ROOT
	oldUserPolicyRoot := prefs.USER_POLICY_ROOT
	oldUserPreferenceRoot := prefs.USER_PREFERENCE_ROOT
	oldRoots := append([]string(nil), prefs.ROOTS...)
	oldRoot := prefs.ROOT

	prefs.MACHINE_POLICY_ROOT = securityPolicyTestRoot + "/airgap_machine_policy"
	prefs.USER_POLICY_ROOT = securityPolicyTestRoot + "/airgap_user_policy"
	prefs.USER_PREFERENCE_ROOT = securityPolicyTestRoot + "/airgap_user_preference"
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

	if err := registry.PutBool(true, prefs.USER_POLICY_ROOT+"/AirGapped"); err != nil {
		t.Fatalf("registry.Put user policy AirGapped: %v", err)
	}

	settings.Load(true)
	if settings.Global().AirGapped {
		t.Fatal("AirGapped = true from HKCU policy, must be ignored")
	}

	if err := registry.PutBool(true, prefs.MACHINE_POLICY_ROOT+"/AirGapped"); err != nil {
		t.Fatalf("registry.Put machine policy AirGapped: %v", err)
	}

	settings.Load(true)
	if !settings.Global().AirGapped {
		t.Fatal("AirGapped = false, want true from HKLM policy")
	}
}

func TestJwksCoseBytesPolicyThenPrefs(t *testing.T) {
	oldMachinePolicyRoot := prefs.MACHINE_POLICY_ROOT
	oldMachinePrefRoot := prefs.MACHINE_PREFERENCE_ROOT

	prefs.MACHINE_POLICY_ROOT = securityPolicyTestRoot + "/jwks_policy"
	prefs.MACHINE_PREFERENCE_ROOT = securityPolicyTestRoot + "/jwks_prefs"

	t.Cleanup(func() {
		_ = exec.Command("reg", "delete", `HKCU\Software\NVMTest\security_policy`, "/f").Run()
		prefs.MACHINE_POLICY_ROOT = oldMachinePolicyRoot
		prefs.MACHINE_PREFERENCE_ROOT = oldMachinePrefRoot
	})

	prefBlob := []byte{0x01, 0x02, 0x03}
	policyBlob := []byte{0xCA, 0xFE}

	if err := registry.Put(prefBlob, prefs.MACHINE_PREFERENCE_ROOT+"/JwksCose"); err != nil {
		t.Fatalf("Put prefs JwksCose: %v", err)
	}
	got := settings.JwksCoseBytes()
	if string(got) != string(prefBlob) {
		t.Fatalf("prefs blob = %v, want %v", got, prefBlob)
	}

	if err := registry.Put(policyBlob, prefs.MACHINE_POLICY_ROOT+"/JwksCose"); err != nil {
		t.Fatalf("Put policy JwksCose: %v", err)
	}
	got = settings.JwksCoseBytes()
	if string(got) != string(policyBlob) {
		t.Fatalf("policy blob = %v, want %v", got, policyBlob)
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

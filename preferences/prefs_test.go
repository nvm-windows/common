package preferences

import (
	"reflect"
	"testing"
)

func TestReloadBuildsPolicyAndPreferenceRoots(t *testing.T) {
	oldOrg := org
	oldSubkey := subkey
	oldApp := app
	oldRoot := ROOT
	oldRoots := append([]string(nil), ROOTS...)
	oldPolicyRoots := append([]string(nil), POLICY_ROOTS...)
	oldACLRoots := append([]string(nil), ACL_ROOTS...)
	oldMachinePreferenceRoot := MACHINE_PREFERENCE_ROOT
	oldUserPreferenceRoot := USER_PREFERENCE_ROOT
	oldMachinePolicyRoot := MACHINE_POLICY_ROOT
	oldUserPolicyRoot := USER_POLICY_ROOT
	oldNVMCommand := NVM_CMD

	t.Cleanup(func() {
		org = oldOrg
		subkey = oldSubkey
		app = oldApp
		ROOT = oldRoot
		ROOTS = oldRoots
		POLICY_ROOTS = oldPolicyRoots
		ACL_ROOTS = oldACLRoots
		MACHINE_PREFERENCE_ROOT = oldMachinePreferenceRoot
		USER_PREFERENCE_ROOT = oldUserPreferenceRoot
		MACHINE_POLICY_ROOT = oldMachinePolicyRoot
		USER_POLICY_ROOT = oldUserPolicyRoot
		NVM_CMD = oldNVMCommand
	})

	org = "Author Software"
	subkey = "Preferences"
	app = "nvm"
	reload()

	if ROOT != "HKCU/Software/Author Software/Preferences/nvm" {
		t.Fatalf("ROOT = %q", ROOT)
	}

	if MACHINE_POLICY_ROOT != "HKLM/SOFTWARE/Policies/Author Software/nvm" {
		t.Fatalf("MACHINE_POLICY_ROOT = %q", MACHINE_POLICY_ROOT)
	}

	if USER_POLICY_ROOT != "HKCU/Software/Policies/Author Software/nvm" {
		t.Fatalf("USER_POLICY_ROOT = %q", USER_POLICY_ROOT)
	}

	if MACHINE_PREFERENCE_ROOT != "HKLM/SOFTWARE/Author Software/Preferences/nvm" {
		t.Fatalf("MACHINE_PREFERENCE_ROOT = %q", MACHINE_PREFERENCE_ROOT)
	}

	wantRoots := []string{
		"HKLM/SOFTWARE/Policies/Author Software/nvm",
		"HKCU/Software/Policies/Author Software/nvm",
		"HKLM/SOFTWARE/Author Software/Preferences/nvm",
		"HKCU/Software/Author Software/Preferences/nvm",
	}
	if !reflect.DeepEqual(ROOTS, wantRoots) {
		t.Fatalf("ROOTS = %#v, want %#v", ROOTS, wantRoots)
	}

	wantACLRoots := []string{
		"HKCU/Software/Policies/Author Software/nvm",
		"HKLM/SOFTWARE/Policies/Author Software/nvm",
		"HKLM/SOFTWARE/Author Software/Preferences/nvm",
	}
	if !reflect.DeepEqual(ACL_ROOTS, wantACLRoots) {
		t.Fatalf("ACL_ROOTS = %#v, want %#v", ACL_ROOTS, wantACLRoots)
	}
}

package settings_test

import (
	"slices"
	"testing"

	"common/settings"
)

func TestListUserCfgExcludesHiddenAndLicensingKeys(t *testing.T) {
	keys := settings.ListUserCfg()

	for _, hidden := range []string{"access_token", "access_key", "active_version"} {
		if slices.Contains(keys, hidden) {
			t.Fatalf("ListUserCfg() contains hidden key %q", hidden)
		}
	}

	if !slices.Contains(keys, "node_mirror") {
		t.Fatal("ListUserCfg() missing public key node_mirror")
	}
	if !slices.Contains(keys, "root") {
		t.Fatal("ListUserCfg() should still expose root for cfg set")
	}
	if !slices.Contains(keys, "proxy") {
		t.Fatal("ListUserCfg() should still expose hidden-doc keys like proxy")
	}
}

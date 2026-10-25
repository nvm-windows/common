package config

import (
	"os/exec"
	"strings"
	"testing"

	prefs "common/preferences"
	"common/settings"
)

func TestPrepareRootRejectsBlank(t *testing.T) {
	prefs.ROOT = "HKCU/Software/NVMTest/config_empty_root"
	prefs.ROOTS = []string{prefs.ROOT}
	t.Cleanup(func() {
		exec.Command("reg", "delete", `HKCU\Software\NVMTest\config_empty_root`, "/f").Run()
	})
	settings.Load(true)

	for _, raw := range []string{"", "   ", `""`, `"   "`} {
		key := "root"
		value := raw
		skip, _, err := Prepare(&key, &value)
		if err == nil || !strings.Contains(err.Error(), "root must be a non-empty path") {
			t.Fatalf("Prepare(root=%q) = skip=%v err=%v, want non-empty path", raw, skip, err)
		}
		if strings.Contains(err.Error(), "NVM4313") {
			t.Fatalf("Prepare(root=%q) used NVM4313: %v", raw, err)
		}
		if !skip {
			t.Fatalf("Prepare(root=%q) skip=false, want true", raw)
		}
	}
}

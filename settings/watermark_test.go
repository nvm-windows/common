package settings_test

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	prefs "common/preferences"
	"common/registry"
	"common/settings"
)

func TestAnnouncementWatermarkPrefersUserOverMachine(t *testing.T) {
	userRoot := testRegistryRoot + "/watermark_user"
	machineRoot := testRegistryRoot + "/watermark_machine"
	oldUser := prefs.USER_PREFERENCE_ROOT
	oldMachine := prefs.MACHINE_PREFERENCE_ROOT
	oldRoot := prefs.ROOT
	oldRoots := append([]string(nil), prefs.ROOTS...)
	prefs.USER_PREFERENCE_ROOT = userRoot
	prefs.MACHINE_PREFERENCE_ROOT = machineRoot
	prefs.ROOT = userRoot
	prefs.ROOTS = []string{machineRoot, userRoot}
	t.Cleanup(func() {
		prefs.USER_PREFERENCE_ROOT = oldUser
		prefs.MACHINE_PREFERENCE_ROOT = oldMachine
		prefs.ROOT = oldRoot
		prefs.ROOTS = oldRoots
		_ = exec.Command("reg", "delete", `HKCU\Software\NVMTest\settings_test\watermark_user`, "/f").Run()
		_ = exec.Command("reg", "delete", `HKCU\Software\NVMTest\settings_test\watermark_machine`, "/f").Run()
		settings.Load(true)
	})

	if err := registry.Put("2020-01-01 00:00:00", machineRoot+"/LastNewsCheck"); err != nil {
		t.Fatalf("seed machine LastNewsCheck: %v", err)
	}
	settings.Load(true)
	got, err := settings.Get("last_news_check")
	if err != nil {
		t.Fatalf("Get(last_news_check): %v", err)
	}
	if strings.TrimSpace(fmt.Sprint(got)) != "2020-01-01 00:00:00" {
		t.Fatalf("machine fallback = %v", got)
	}

	if err := settings.Put("last_news_check", "2026-08-08 12:00:00"); err != nil {
		t.Fatalf("Put user LastNewsCheck: %v", err)
	}
	settings.Load(true)
	got, err = settings.Get("last_news_check")
	if err != nil {
		t.Fatalf("Get after user put: %v", err)
	}
	if strings.TrimSpace(fmt.Sprint(got)) != "2026-08-08 12:00:00" {
		t.Fatalf("user should win, got %v", got)
	}
}

func TestSeedAnnouncementWatermarksIfEmptySkipsExisting(t *testing.T) {
	t.Cleanup(func() {
		_ = settings.Del("last_news_check")
		settings.Load(true)
	})
	if err := settings.Put("last_news_check", "2024-01-01 00:00:00"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := settings.SeedAnnouncementWatermarksIfEmpty(settings.Put); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := settings.Get("last_news_check")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.TrimSpace(fmt.Sprint(got)) != "2024-01-01 00:00:00" {
		t.Fatalf("seed overwrote existing = %v", got)
	}
}

package settings_test

import (
	"slices"
	"testing"

	"common/settings"
)

func TestIsExcludedFromBulkReset(t *testing.T) {
	for _, name := range []string{"root", "active_version", "access_token", "access_key"} {
		if !settings.IsExcludedFromBulkReset(name) {
			t.Fatalf("IsExcludedFromBulkReset(%q) = false, want true", name)
		}
	}

	for _, name := range []string{"mode", "auto_install", "node_mirror"} {
		if settings.IsExcludedFromBulkReset(name) {
			t.Fatalf("IsExcludedFromBulkReset(%q) = true, want false", name)
		}
	}
}

func TestBulkResetCandidatesExcludeProtectedKeys(t *testing.T) {
	for _, name := range settings.List() {
		if settings.IsExcludedFromBulkReset(name) {
			continue
		}
		if slices.Contains([]string{"root", "active_version", "access_token", "access_key"}, name) {
			t.Fatalf("bulk reset candidate list includes protected key %q", name)
		}
	}
}

package resolver

import "testing"

func TestFindExactVersionSkipsCatalog(t *testing.T) {
	for _, spec := range []string{"24.22.1", "v24.22.1", "24.22.1-rc.1"} {
		got, npm, err := Find(spec)
		if err != nil {
			t.Fatalf("Find(%q) error = %v", spec, err)
		}
		if got != "24.22.1" {
			t.Fatalf("Find(%q) = %q, want 24.22.1", spec, got)
		}
		if npm != "" {
			t.Fatalf("Find(%q) npm = %q, want empty (no catalog)", spec, npm)
		}
	}
}

func TestLatestStableSkipsPrereleaseHead(t *testing.T) {
	// Mirrors nodejs.org/dist/index.tab order when an alpha leads the catalog.
	rows := [][]string{
		{"27.0.0-alpha.0.0.0", "2026-10-29", "12.1.0", "", "-"},
		{"26.13.0", "2026-10-28", "11.20.0", "Lithium", "-"},
		{"26.12.1", "2026-10-21", "11.20.0", "", "true"},
	}
	got, err := latestStable(rows)
	if err != nil {
		t.Fatalf("latestStable error = %v", err)
	}
	if got != "26.13.0" {
		t.Fatalf("latestStable = %q, want 26.13.0", got)
	}
}

func TestLatestStableEmptyOrOnlyPrerelease(t *testing.T) {
	if _, err := latestStable(nil); err == nil {
		t.Fatal("expected error for empty catalog")
	}
	if _, err := latestStable([][]string{{"27.0.0-alpha.0.0.0", "", "", "", ""}}); err == nil {
		t.Fatal("expected error when only prereleases exist")
	}
}

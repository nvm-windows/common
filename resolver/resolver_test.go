package resolver

import "testing"

func TestFindExactVersionSkipsCatalog(t *testing.T) {
	for _, spec := range []string{"24.22.1", "v24.22.1"} {
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

func TestFindExactPrereleaseKeepsTag(t *testing.T) {
	got, npm, err := Find("24.22.1-rc.1")
	if err != nil {
		t.Fatalf("Find(prerelease) error = %v", err)
	}
	if got != "24.22.1-rc.1" {
		t.Fatalf("Find(prerelease) = %q, want 24.22.1-rc.1", got)
	}
	if npm != "" {
		t.Fatalf("Find(prerelease) npm = %q, want empty (no catalog)", npm)
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

func TestLatestAlphaPicksLeadingAlpha(t *testing.T) {
	rows := [][]string{
		{"27.0.0-alpha.0.0.0", "2026-10-29", "12.1.0", "", "-"},
		{"26.13.0", "2026-10-28", "11.20.0", "Lithium", "-"},
		{"26.0.0-alpha.1", "2026-01-01", "11.0.0", "", "-"},
	}
	got, err := latestAlpha(rows)
	if err != nil {
		t.Fatalf("latestAlpha error = %v", err)
	}
	if got != "27.0.0-alpha.0.0.0" {
		t.Fatalf("latestAlpha = %q, want 27.0.0-alpha.0.0.0", got)
	}
}

func TestLatestAlphaNone(t *testing.T) {
	if _, err := latestAlpha([][]string{{"26.13.0", "", "", "", ""}}); err == nil {
		t.Fatal("expected error when no alphas exist")
	}
}

func TestLatestTipReturnsPrereleaseHead(t *testing.T) {
	rows := [][]string{
		{"27.0.0-alpha.0.0.0", "2026-10-29", "12.1.0", "", "-"},
		{"26.13.0", "2026-10-28", "11.20.0", "Lithium", "-"},
	}
	got, err := latestTip(rows)
	if err != nil {
		t.Fatalf("latestTip error = %v", err)
	}
	if got != "27.0.0-alpha.0.0.0" {
		t.Fatalf("latestTip = %q, want 27.0.0-alpha.0.0.0", got)
	}
}

func TestIsAlphaAndUnstableHelpers(t *testing.T) {
	if !IsAlphaVersion("v27.0.0-alpha.0.0.0") {
		t.Fatal("expected alpha")
	}
	if IsAlphaVersion("27.0.0-rc.1") {
		t.Fatal("rc must not count as alpha")
	}
	if !IsUnstableVersion("27.0.0-rc.1") {
		t.Fatal("expected unstable")
	}
	if IsUnstableVersion("27.0.0") {
		t.Fatal("GA must be stable")
	}
}

func TestCanonicalVersion(t *testing.T) {
	if got := CanonicalVersion("V27.0.0-Alpha.0.0.0"); got != "27.0.0-alpha.0.0.0" {
		t.Fatalf("CanonicalVersion = %q", got)
	}
}

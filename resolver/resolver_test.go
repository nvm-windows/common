package resolver

import (
	"strings"
	"testing"
)

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

func TestBestPartialCatalogMatchPrefersStableOverNewerAlpha(t *testing.T) {
	// Newer alpha first (index.tab tip), older GA second — partial "27" must pick GA.
	rows := [][]string{
		{"27.1.0-alpha.0.0.0", "2027-05-01", "12.2.0", "", "-"},
		{"27.0.5", "2027-04-15", "12.1.0", "", "-"},
		{"27.0.0-alpha.0.1.0", "2027-01-10", "12.0.0", "", "-"},
		{"26.13.0", "2026-10-28", "11.20.0", "Lithium", "-"},
	}
	got, npm, ok := bestPartialCatalogMatch(rows, "27", "", "")
	if !ok {
		t.Fatal("expected a match for major 27")
	}
	if got != "27.0.5" {
		t.Fatalf("bestPartialCatalogMatch(27) = %q, want 27.0.5 (stable over newer alpha)", got)
	}
	if npm != "12.1.0" {
		t.Fatalf("npm = %q, want 12.1.0", npm)
	}
}

func TestBestPartialCatalogMatchFallsBackToPrerelease(t *testing.T) {
	rows := [][]string{
		{"27.0.0-alpha.0.1.0", "2027-01-10", "12.0.1", "", "-"},
		{"27.0.0-alpha.0.0.0", "2027-01-01", "12.0.0", "", "-"},
		{"26.13.0", "2026-10-28", "11.20.0", "Lithium", "-"},
	}
	got, _, ok := bestPartialCatalogMatch(rows, "27", "", "")
	if !ok {
		t.Fatal("expected prerelease fallback for alpha-only major 27")
	}
	if got != "27.0.0-alpha.0.1.0" {
		t.Fatalf("bestPartialCatalogMatch(27) = %q, want newest alpha", got)
	}
}

func TestBestPartialCatalogMatchMajorMinorPrefersStable(t *testing.T) {
	rows := [][]string{
		{"27.0.1-alpha.1", "2027-02-01", "12.0.2", "", "-"},
		{"27.0.0", "2027-01-15", "12.0.0", "", "-"},
		{"27.0.0-alpha.0.0.0", "2027-01-01", "12.0.0", "", "-"},
	}
	got, _, ok := bestPartialCatalogMatch(rows, "27", "0", "")
	if !ok {
		t.Fatal("expected match for 27.0")
	}
	if got != "27.0.0" {
		t.Fatalf("bestPartialCatalogMatch(27.0) = %q, want 27.0.0", got)
	}
}

func TestLatestInstalledMatchPrefersStableOverNewerAlpha(t *testing.T) {
	installed := []string{
		"27.1.0-alpha.0.0.0",
		"27.0.5",
		"27.0.0-alpha.0.1.0",
		"26.13.0",
	}
	got, ok := LatestInstalledMatch("27", installed)
	if !ok {
		t.Fatal("expected installed match for 27")
	}
	if got != "27.0.5" {
		t.Fatalf("LatestInstalledMatch(27) = %q, want 27.0.5", got)
	}
}

func TestLatestInstalledMatchFallsBackToPrerelease(t *testing.T) {
	installed := []string{"27.0.0-alpha.0.1.0", "27.0.0-alpha.0.0.0", "26.13.0"}
	got, ok := LatestInstalledMatch("27", installed)
	if !ok {
		t.Fatal("expected prerelease fallback")
	}
	if got != "27.0.0-alpha.0.1.0" {
		t.Fatalf("LatestInstalledMatch(27) = %q, want newest alpha tag (canonical)", got)
	}
}

func TestLatestInstalledAlphaIgnoresStableAndRC(t *testing.T) {
	installed := []string{
		"27.0.0",
		"27.0.0-rc.1",
		"27.0.0-alpha.0.1.0",
		"26.0.0-alpha.1",
	}
	got, ok := LatestInstalledAlpha(installed)
	if !ok {
		t.Fatal("expected an installed alpha")
	}
	if got != "27.0.0-alpha.0.1.0" {
		t.Fatalf("LatestInstalledAlpha = %q, want 27.0.0-alpha.0.1.0", got)
	}
}

func TestLatestInstalledAlphaNone(t *testing.T) {
	if _, ok := LatestInstalledAlpha([]string{"27.0.0", "27.0.0-rc.1"}); ok {
		t.Fatal("expected no alpha match")
	}
}

func fixtureLTSRows() [][]string {
	// Newest-first catalog: two patches per LTS line plus non-LTS rows.
	return [][]string{
		{"24.11.0", "2026-10-28", "11.6.0", "Krypton", "-"},
		{"24.10.0", "2026-09-01", "11.5.0", "Krypton", "-"},
		{"23.0.0", "2026-08-01", "11.0.0", "", "-"},
		{"22.20.0", "2026-07-01", "10.9.0", "Jod", "-"},
		{"22.19.0", "2026-06-01", "10.8.0", "Jod", "-"},
		{"20.19.0", "2026-05-01", "10.8.0", "Iron", "-"},
		{"20.18.0", "2026-04-01", "10.7.0", "Iron", "-"},
	}
}

func TestUniqueLTSLinesNewestPerCodename(t *testing.T) {
	lines := uniqueLTSLines(fixtureLTSRows())
	if len(lines) != 3 {
		t.Fatalf("uniqueLTSLines len = %d, want 3", len(lines))
	}
	want := []ltsLine{
		{name: "Krypton", version: "24.11.0"},
		{name: "Jod", version: "22.20.0"},
		{name: "Iron", version: "20.19.0"},
	}
	for i, got := range lines {
		if got.name != want[i].name || got.version != want[i].version {
			t.Fatalf("lines[%d] = %+v, want %+v", i, got, want[i])
		}
	}
}

func TestResolveLTSOffsetHappyPath(t *testing.T) {
	rows := fixtureLTSRows()
	got, err := resolveLTSOffset(rows, 1)
	if err != nil {
		t.Fatalf("resolveLTSOffset(1) error = %v", err)
	}
	if got != "22.20.0" {
		t.Fatalf("resolveLTSOffset(1) = %q, want 22.20.0", got)
	}
	got, err = resolveLTSOffset(rows, 2)
	if err != nil {
		t.Fatalf("resolveLTSOffset(2) error = %v", err)
	}
	if got != "20.19.0" {
		t.Fatalf("resolveLTSOffset(2) = %q, want 20.19.0", got)
	}
}

func TestResolveLTSOffsetOutOfRange(t *testing.T) {
	rows := fixtureLTSRows() // 3 unique lines → max offset -2
	_, err := resolveLTSOffset(rows, 99)
	if err == nil {
		t.Fatal("expected out-of-range error")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error = %q, want out of range", err)
	}
	if !strings.Contains(err.Error(), "lts/-2") {
		t.Fatalf("error = %q, want hint up to lts/-2", err)
	}
}

func TestResolveLTSOffsetNoLTS(t *testing.T) {
	_, err := resolveLTSOffset([][]string{{"23.0.0", "", "", "", ""}}, 1)
	if err == nil || !strings.Contains(err.Error(), "no LTS version found") {
		t.Fatalf("error = %v, want no LTS version found", err)
	}
}

func TestParseLTSOffsetValid(t *testing.T) {
	n, ok, err := parseLTSOffset("-1")
	if !ok || err != nil || n != 1 {
		t.Fatalf("parseLTSOffset(-1) = %d, %v, %v", n, ok, err)
	}
	n, ok, err = parseLTSOffset("-12")
	if !ok || err != nil || n != 12 {
		t.Fatalf("parseLTSOffset(-12) = %d, %v, %v", n, ok, err)
	}
}

func TestParseLTSOffsetCodenamePath(t *testing.T) {
	_, ok, err := parseLTSOffset("iron")
	if ok || err != nil {
		t.Fatalf("parseLTSOffset(iron) ok=%v err=%v, want codename path", ok, err)
	}
}

func TestParseLTSOffsetInvalidSyntax(t *testing.T) {
	cases := []string{"-0", "-", "-1x", "--1", "-10+1"}
	for _, name := range cases {
		_, ok, err := parseLTSOffset(name)
		if !ok {
			t.Fatalf("parseLTSOffset(%q) ok=false, want offset path", name)
		}
		if err == nil {
			t.Fatalf("parseLTSOffset(%q) expected syntax error", name)
		}
		if !strings.Contains(err.Error(), "invalid LTS offset") {
			t.Fatalf("parseLTSOffset(%q) error = %q, want invalid LTS offset", name, err)
		}
		if !strings.Contains(err.Error(), "lts/-1") {
			t.Fatalf("parseLTSOffset(%q) error = %q, want example lts/-1", name, err)
		}
	}
}

func TestParseLTSOffsetNeverCodenameForDashNames(t *testing.T) {
	// Regression: lts/-1 must not fall through to EqualFold codename lookup.
	_, ok, err := parseLTSOffset("-1")
	if !ok || err != nil {
		t.Fatalf("parseLTSOffset(-1) = ok=%v err=%v", ok, err)
	}
}

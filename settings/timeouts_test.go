package settings

import (
	"testing"
	"time"
)

func sampleBudgets() NetworkBudgets {
	return NetworkBudgets{
		Catalog:       Budget{Milliseconds: DefaultTimeoutCatalogMs, Source: SourceDefault},
		CatalogMirror: Budget{Milliseconds: DefaultTimeoutCatalogMirrorMs, Source: SourceDefault},
		Reachability:  Budget{Milliseconds: DefaultTimeoutReachabilityMs, Source: SourceDefault},
		Download:      Budget{Milliseconds: DefaultTimeoutDownloadMs, Source: SourceDefault},
	}
}

func TestApplyRelaxAbsentKeepsDefaults(t *testing.T) {
	got := ApplyRelax(sampleBudgets(), RelaxDeadlines{})
	if got.Verbose || got.Catalog.Milliseconds != 3000 || got.Catalog.Source != SourceDefault {
		t.Fatalf("absent flag changed budgets: %+v", got)
	}
	if got.Download.Milliseconds != 30000 {
		t.Fatalf("download = %d", got.Download.Milliseconds)
	}
}

func TestApplyRelaxTriples(t *testing.T) {
	got := ApplyRelax(sampleBudgets(), RelaxDeadlines{Active: true})
	if !got.Verbose {
		t.Fatal("expected verbose")
	}
	if got.Catalog.Milliseconds != 9000 || got.CatalogMirror.Milliseconds != 2400 || got.Reachability.Milliseconds != 4500 || got.Download.Milliseconds != 90000 {
		t.Fatalf("triple = %+v", got)
	}
	if got.Catalog.Source != SourceCommandFlag || got.Download.Source != SourceCommandFlag {
		t.Fatalf("source = %s", got.Catalog.Source)
	}
}

func TestApplyRelaxCustomDoesNotShrinkDownload(t *testing.T) {
	got := ApplyRelax(sampleBudgets(), RelaxDeadlines{Active: true, Milliseconds: 9000})
	if got.Catalog.Milliseconds != 9000 || got.CatalogMirror.Milliseconds != 9000 || got.Reachability.Milliseconds != 9000 {
		t.Fatalf("custom catalog budgets = %+v", got)
	}
	if got.Download.Milliseconds != 30000 || got.Download.Source != SourceCommandFlag {
		t.Fatalf("download = %+v", got.Download)
	}

	raised := ApplyRelax(sampleBudgets(), RelaxDeadlines{Active: true, Milliseconds: 120000})
	if raised.Download.Milliseconds != 120000 {
		t.Fatalf("raised download = %d", raised.Download.Milliseconds)
	}
}

func TestApplyStepDeadlinesOverridesOneStep(t *testing.T) {
	got := ApplyStepDeadlines(sampleBudgets(), StepDeadlines{CatalogMirrorMs: 3000})
	if !got.Verbose {
		t.Fatal("expected verbose")
	}
	if got.CatalogMirror.Milliseconds != 3000 || got.CatalogMirror.Source != SourceCommandFlag {
		t.Fatalf("mirror = %+v", got.CatalogMirror)
	}
	if got.Catalog.Milliseconds != 3000 || got.Catalog.Source != SourceDefault {
		t.Fatalf("catalog = %+v", got.Catalog)
	}
	if got.Reachability.Milliseconds != 1500 || got.Reachability.Source != SourceDefault {
		t.Fatalf("reachability = %+v", got.Reachability)
	}
	if got.Download.Milliseconds != 30000 || got.Download.Source != SourceDefault {
		t.Fatalf("download = %+v", got.Download)
	}
}

func TestApplyStepDeadlinesWinsOverRelax(t *testing.T) {
	relaxed := ApplyRelax(sampleBudgets(), RelaxDeadlines{Active: true})
	got := ApplyStepDeadlines(relaxed, StepDeadlines{CatalogMirrorMs: 5000})
	if got.Catalog.Milliseconds != 9000 || got.Reachability.Milliseconds != 4500 || got.Download.Milliseconds != 90000 {
		t.Fatalf("relaxed steps = %+v", got)
	}
	if got.CatalogMirror.Milliseconds != 5000 || got.CatalogMirror.Source != SourceCommandFlag {
		t.Fatalf("mirror = %+v", got.CatalogMirror)
	}
}

func TestApplyStepDeadlinesCanShrinkDownload(t *testing.T) {
	got := ApplyStepDeadlines(sampleBudgets(), StepDeadlines{DownloadMs: 5000})
	if got.Download.Milliseconds != 5000 || got.Download.Source != SourceCommandFlag {
		t.Fatalf("download = %+v", got.Download)
	}
}

func TestAutoDeadlineAttempts(t *testing.T) {
	if got := AutoDeadlineAttempts(); got != 59 {
		t.Fatalf("attempts = %d, want 59", got)
	}
}

func TestSuggestedDeadlineMs(t *testing.T) {
	if got := SuggestedDeadlineMs(1234*time.Millisecond, DefaultTimeoutCatalogMirrorMs); got != 1234 {
		t.Fatalf("mirror = %d, want 1234", got)
	}
	if got := SuggestedDeadlineMs(1234*time.Millisecond, DefaultTimeoutCatalogMs); got != DefaultTimeoutCatalogMs {
		t.Fatalf("catalog = %d, want default", got)
	}
	if got := SuggestedDeadlineMs(200*time.Millisecond, DefaultTimeoutDownloadMs); got != DefaultTimeoutDownloadMs {
		t.Fatalf("download = %d, want default", got)
	}
	if got := SuggestedDeadlineMs(16297*time.Millisecond, DefaultTimeoutReachabilityMs); got != 16297 {
		t.Fatalf("reachability = %d, want 16297", got)
	}
}

func TestParseRelaxDeadlines(t *testing.T) {
	absent, err := ParseRelaxDeadlines([]string{"install", "20"})
	if err != nil || absent.Active {
		t.Fatalf("absent = %+v %v", absent, err)
	}
	bare, err := ParseRelaxDeadlines([]string{"install", "--relax-deadlines", "lts"})
	if err != nil || !bare.Active || bare.Milliseconds != 0 {
		t.Fatalf("bare = %+v %v", bare, err)
	}
	spaced, err := ParseRelaxDeadlines([]string{"--relax-deadlines", "9000", "20"})
	if err != nil || spaced.Milliseconds != 9000 {
		t.Fatalf("spaced = %+v %v", spaced, err)
	}
	custom, err := ParseRelaxDeadlines([]string{"--relax-deadlines=9000"})
	if err != nil || custom.Milliseconds != 9000 {
		t.Fatalf("custom = %+v %v", custom, err)
	}
	if _, err := ParseRelaxDeadlines([]string{"--relax-deadlines=0"}); err == nil {
		t.Fatal("expected rejection of 0")
	}
}

func TestBudgetNote(t *testing.T) {
	if got := (Budget{Milliseconds: 800, Source: SourceDefault}).Note(); got != "800ms (default)" {
		t.Fatalf("note = %q", got)
	}
}

package resolver

import (
	"testing"
	"time"
)

func TestPerMirrorBudgetFairShare(t *testing.T) {
	// Three mirrors left, 3s remaining → each gets 1s fair share, capped at 800ms.
	got := perMirrorBudget(3, catalogOverallBudget)
	if got != catalogPerMirrorCap {
		t.Fatalf("perMirrorBudget(3, 3s) = %v, want %v", got, catalogPerMirrorCap)
	}
}

func TestPerMirrorBudgetRespectsRemaining(t *testing.T) {
	// fair share 150ms < floor → floor 200ms, still under remaining 300ms.
	got := perMirrorBudget(2, 300*time.Millisecond)
	if got != catalogPerMirrorFloor {
		t.Fatalf("perMirrorBudget = %v, want floor %v", got, catalogPerMirrorFloor)
	}
}

func TestPerMirrorBudgetClampsToRemaining(t *testing.T) {
	got := perMirrorBudget(1, 100*time.Millisecond)
	if got != 100*time.Millisecond {
		t.Fatalf("perMirrorBudget = %v, want 100ms", got)
	}
}

func TestPerMirrorBudgetZeroRemaining(t *testing.T) {
	if got := perMirrorBudget(5, 0); got != 0 {
		t.Fatalf("perMirrorBudget = %v, want 0", got)
	}
}

func TestParseIndexTabFiltersMajor(t *testing.T) {
	body := []byte("version\tdate\tfiles\tnpm\tv8\tuv\tzlib\topenssl\tmodules\tlts\tsecurity\n" +
		"v22.0.0\t2024-01-01\t-\t10.0.0\t-\t-\t-\t-\t-\tIron\t-\n" +
		"v20.0.0\t2024-01-01\t-\t9.0.0\t-\t-\t-\t-\t-\tIron\t-\n")
	got := parseIndexTab(body, map[string]bool{"22": true})
	if len(got) != 1 || got[0][0] != "22.0.0" {
		t.Fatalf("parseIndexTab = %#v", got)
	}
}

func TestCatalogMemoryTTL(t *testing.T) {
	catalogMemMu.Lock()
	catalogMemBody = nil
	catalogMemAt = time.Time{}
	catalogMemMu.Unlock()

	setCatalogMemory([]byte("hello"))
	body, ok := catalogMemory()
	if !ok || string(body) != "hello" {
		t.Fatalf("catalogMemory = %q ok=%v", body, ok)
	}

	catalogMemMu.Lock()
	catalogMemAt = time.Now().Add(-catalogCacheTTL - time.Second)
	catalogMemMu.Unlock()
	if _, ok := catalogMemory(); ok {
		t.Fatal("expected expired catalog memory miss")
	}
}

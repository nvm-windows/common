package resolver

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPerMirrorBudgetFairShare(t *testing.T) {
	got := perMirrorBudget(3, 3*time.Second, 800*time.Millisecond)
	if got != 800*time.Millisecond {
		t.Fatalf("perMirrorBudget(3, 3s, 800ms) = %v, want 800ms", got)
	}
}

func TestPerMirrorBudgetFairShareWithoutFloor(t *testing.T) {
	got := perMirrorBudget(2, 300*time.Millisecond, 800*time.Millisecond)
	if got != 150*time.Millisecond {
		t.Fatalf("perMirrorBudget = %v, want 150ms", got)
	}
}

func TestPerMirrorBudgetClampsToRemaining(t *testing.T) {
	got := perMirrorBudget(1, 100*time.Millisecond, 800*time.Millisecond)
	if got != 100*time.Millisecond {
		t.Fatalf("perMirrorBudget = %v, want 100ms", got)
	}
}

func TestPerMirrorBudgetZeroRemaining(t *testing.T) {
	if got := perMirrorBudget(5, 0, 800*time.Millisecond); got != 0 {
		t.Fatalf("perMirrorBudget = %v, want 0", got)
	}
}

func TestDeadlineErrorNamesAppliedBudget(t *testing.T) {
	err := &DeadlineError{
		Phase: "mirror", URL: "https://nodejs.org/dist/index.tab",
		CatalogMs: 3000, CatalogSource: "default",
		MirrorMs: 800, MirrorSource: "default",
		Err: fmt.Errorf("context deadline exceeded"),
	}
	msg := err.Error()
	if !strings.Contains(msg, "TimeoutCatalogMirrorMs 800ms, default") || !strings.Contains(msg, "TimeoutCatalogMs 3000ms, default") {
		t.Fatalf("message = %s", msg)
	}
	err.Verbose = true
	if !strings.Contains(err.Error(), "phase=mirror url=https://nodejs.org/dist/index.tab") {
		t.Fatalf("verbose = %s", err.Error())
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

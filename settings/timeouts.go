package settings

import (
	prefs "common/preferences"
	"common/registry"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTimeoutCatalogMs       = 3000
	DefaultTimeoutCatalogMirrorMs = 800
	DefaultTimeoutReachabilityMs  = 1500
	DefaultTimeoutDownloadMs      = 30000

	// Auto-deadline estimand: 95th percentile of request latency.
	// Confidence 95%. Method: sample maximum (order statistic).
	// n = ceil(ln(1-confidence) / ln(percentile)) = 59.
	autoDeadlineConfidence = 0.95
	autoDeadlinePercentile = 0.95

	SourceMachinePolicy   = "machine policy"
	SourceMachineSettings = "machine settings"
	SourceYourSettings    = "your settings"
	SourceDefault         = "default"
	SourceCommandFlag     = "command flag"
)

// Budget is one resolved millisecond deadline and the place it came from.
type Budget struct {
	Milliseconds int
	Source       string
}

func (b Budget) Duration() time.Duration {
	if b.Milliseconds <= 0 {
		return 0
	}
	return time.Duration(b.Milliseconds) * time.Millisecond
}

func (b Budget) Note() string {
	source := b.Source
	if source == "" {
		source = SourceDefault
	}
	return fmt.Sprintf("%dms (%s)", b.Milliseconds, source)
}

// NetworkBudgets holds the four deadlines for one command.
type NetworkBudgets struct {
	Catalog       Budget
	CatalogMirror Budget
	Reachability  Budget
	Download      Budget
	Verbose       bool
}

// RelaxDeadlines is the --relax-deadlines flag for one command.
// Milliseconds 0 means triple each resolved budget.
type RelaxDeadlines struct {
	Active       bool
	Milliseconds int
}

var (
	budgetMu  sync.Mutex
	budgetSet bool
	active    NetworkBudgets
)

func invalidateNetworkBudgets() {
	budgetMu.Lock()
	budgetSet = false
	budgetMu.Unlock()
}

// UseNetworkBudgets stores the deadlines for the rest of this process.
func UseNetworkBudgets(b NetworkBudgets) {
	budgetMu.Lock()
	active = b
	budgetSet = true
	budgetMu.Unlock()
}

// StepDeadlines overrides individual deadlines for one command.
// A value of 0 leaves that step unchanged.
type StepDeadlines struct {
	CatalogMs       int
	CatalogMirrorMs int
	ReachabilityMs  int
	DownloadMs      int
}

// UseRelax resolves registry deadlines, applies the flag, and stores them.
func UseRelax(relax RelaxDeadlines) NetworkBudgets {
	return UseCommandDeadlines(relax, StepDeadlines{})
}

// UseCommandDeadlines resolves registry deadlines, applies relax, then per-step flags.
// A per-step value replaces only that step and wins over relax.
func UseCommandDeadlines(relax RelaxDeadlines, steps StepDeadlines) NetworkBudgets {
	b := ApplyStepDeadlines(ResolveNetworkBudgets(relax), steps)
	UseNetworkBudgets(b)
	return b
}

// ActiveNetworkBudgets returns the deadlines for this process.
// The first call resolves registry values with no flag.
func ActiveNetworkBudgets() NetworkBudgets {
	budgetMu.Lock()
	if budgetSet {
		b := active
		budgetMu.Unlock()
		return b
	}
	budgetMu.Unlock()
	b := resolveNetworkBudgets(RelaxDeadlines{})
	UseNetworkBudgets(b)
	return b
}

// ResolveNetworkBudgets reads the four timeout settings and applies relax.
func ResolveNetworkBudgets(relax RelaxDeadlines) NetworkBudgets {
	return resolveNetworkBudgets(relax)
}

func resolveNetworkBudgets(relax RelaxDeadlines) NetworkBudgets {
	cfg := Global()
	b := NetworkBudgets{
		Catalog: Budget{
			Milliseconds: positiveOrDefault(cfg.TimeoutCatalogMs, DefaultTimeoutCatalogMs),
			Source:       SettingSource("timeout_catalog_ms"),
		},
		CatalogMirror: Budget{
			Milliseconds: positiveOrDefault(cfg.TimeoutCatalogMirrorMs, DefaultTimeoutCatalogMirrorMs),
			Source:       SettingSource("timeout_catalog_mirror_ms"),
		},
		Reachability: Budget{
			Milliseconds: positiveOrDefault(cfg.TimeoutReachabilityMs, DefaultTimeoutReachabilityMs),
			Source:       SettingSource("timeout_reachability_ms"),
		},
		Download: Budget{
			Milliseconds: positiveOrDefault(cfg.TimeoutDownloadMs, DefaultTimeoutDownloadMs),
			Source:       SettingSource("timeout_download_ms"),
		},
	}
	return ApplyRelax(b, relax)
}

func positiveOrDefault(ms, fallback int) int {
	if ms <= 0 {
		return fallback
	}
	return ms
}

// ApplyRelax adjusts already-resolved budgets for one command.
func ApplyRelax(b NetworkBudgets, relax RelaxDeadlines) NetworkBudgets {
	if !relax.Active {
		return b
	}
	b.Verbose = true
	if relax.Milliseconds <= 0 {
		b.Catalog.Milliseconds *= 3
		b.CatalogMirror.Milliseconds *= 3
		b.Reachability.Milliseconds *= 3
		b.Download.Milliseconds *= 3
	} else {
		b.Catalog.Milliseconds = relax.Milliseconds
		b.CatalogMirror.Milliseconds = relax.Milliseconds
		b.Reachability.Milliseconds = relax.Milliseconds
		if b.Download.Milliseconds < relax.Milliseconds {
			b.Download.Milliseconds = relax.Milliseconds
		}
	}
	b.Catalog.Source = SourceCommandFlag
	b.CatalogMirror.Source = SourceCommandFlag
	b.Reachability.Source = SourceCommandFlag
	b.Download.Source = SourceCommandFlag
	return b
}

// ApplyStepDeadlines replaces only the steps whose millisecond value is positive.
func ApplyStepDeadlines(b NetworkBudgets, steps StepDeadlines) NetworkBudgets {
	set := func(budget *Budget, ms int) {
		if ms <= 0 {
			return
		}
		budget.Milliseconds = ms
		budget.Source = SourceCommandFlag
		b.Verbose = true
	}
	set(&b.Catalog, steps.CatalogMs)
	set(&b.CatalogMirror, steps.CatalogMirrorMs)
	set(&b.Reachability, steps.ReachabilityMs)
	set(&b.Download, steps.DownloadMs)
	return b
}

// SettingSource reports where the named setting's effective value comes from.
// The first existing value in registry precedence wins. A missing key is default.
func SettingSource(cfgName string) string {
	regName := key(cfgName)
	if regName == "" {
		return SourceDefault
	}
	for _, root := range prefs.ROOTS {
		_, exists, err := registry.Get(root + "/" + regName)
		if err == nil && exists {
			return sourceLabel(root)
		}
	}
	return SourceDefault
}

func sourceLabel(root string) string {
	switch root {
	case prefs.MACHINE_POLICY_ROOT:
		return SourceMachinePolicy
	case prefs.MACHINE_PREFERENCE_ROOT:
		return SourceMachineSettings
	default:
		return SourceYourSettings
	}
}

// HKCUWriteChangesEffective reports whether a user-preference write can win.
// Machine policy and machine settings are earlier in the load order.
func HKCUWriteChangesEffective(cfgName string) (bool, string) {
	regName := key(cfgName)
	if regName == "" {
		return true, ""
	}
	for _, root := range prefs.ROOTS {
		if root == prefs.USER_PREFERENCE_ROOT || root == prefs.ROOT {
			return true, ""
		}
		_, exists, err := registry.Get(root + "/" + regName)
		if err == nil && exists {
			return false, sourceLabel(root)
		}
	}
	return true, ""
}

// AutoDeadlineAttempts is how many attempts make the sample maximum a 95% upper bound on the 95th percentile.
func AutoDeadlineAttempts() int {
	n := math.Ceil(math.Log(1-autoDeadlineConfidence) / math.Log(autoDeadlinePercentile))
	if n < 1 {
		return 1
	}
	return int(n)
}

// SuggestedDeadlineMs rounds the sample maximum up to milliseconds, never below floorMs.
// That maximum is the auto-deadline estimate after AutoDeadlineAttempts samples.
func SuggestedDeadlineMs(maximum time.Duration, floorMs int) int {
	if maximum < 0 {
		maximum = 0
	}
	ms := int((maximum + time.Millisecond - 1) / time.Millisecond)
	if ms < floorMs {
		return floorMs
	}
	return ms
}

// SaveAutoDeadlines writes HKCU millisecond values from sample maxima.
// reachMax feeds TimeoutReachabilityMs. manifestMax feeds the catalog, per-mirror, and download keys.
// Each saved value is at least that setting's default. Notes describe each write. A policy block is reported and skipped.
func SaveAutoDeadlines(reachMax, manifestMax time.Duration) []string {
	items := []struct {
		name  string
		max   time.Duration
		floor int
	}{
		{"timeout_reachability_ms", reachMax, DefaultTimeoutReachabilityMs},
		{"timeout_catalog_ms", manifestMax, DefaultTimeoutCatalogMs},
		{"timeout_catalog_mirror_ms", manifestMax, DefaultTimeoutCatalogMirrorMs},
		{"timeout_download_ms", manifestMax, DefaultTimeoutDownloadMs},
	}
	notes := make([]string, 0, len(items))
	for _, item := range items {
		ms := SuggestedDeadlineMs(item.max, item.floor)
		regName := key(item.name)
		if ok, src := HKCUWriteChangesEffective(item.name); !ok {
			notes = append(notes, fmt.Sprintf("%s is enforced by %s; saving your settings will not change the effective deadline", regName, src))
			continue
		}
		if err := Put(item.name, strconv.Itoa(ms)); err != nil {
			notes = append(notes, err.Error())
			continue
		}
		notes = append(notes, fmt.Sprintf("%s set to %dms (your settings)", regName, ms))
	}
	Load(true)
	return notes
}

// ParseRelaxDeadlines reads --relax-deadlines from args.
// A bare flag triples budgets. A positive integer replaces catalog, mirror, and reachability.
func ParseRelaxDeadlines(args []string) (RelaxDeadlines, error) {
	var out RelaxDeadlines
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if a == "--relax-deadlines" {
			out.Active = true
			if i+1 < len(args) && millisToken(args[i+1]) {
				n, err := strconv.Atoi(args[i+1])
				if err != nil || n <= 0 {
					return out, fmt.Errorf("--relax-deadlines must be a positive number of milliseconds")
				}
				out.Milliseconds = n
			}
			return out, nil
		}
		if raw, ok := strings.CutPrefix(a, "--relax-deadlines="); ok {
			out.Active = true
			if raw == "" {
				return out, nil
			}
			n, err := strconv.Atoi(raw)
			if err != nil || n <= 0 {
				return out, fmt.Errorf("--relax-deadlines must be a positive number of milliseconds")
			}
			out.Milliseconds = n
			return out, nil
		}
	}
	return out, nil
}

func millisToken(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

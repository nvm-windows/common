package http

import (
	"testing"
	"time"
)

func TestProbeAverage(t *testing.T) {
	p := ProbeResult{Samples: []time.Duration{100 * time.Millisecond, 300 * time.Millisecond}}
	if p.Min() != 100*time.Millisecond || p.Max() != 300*time.Millisecond || p.Average() != 200*time.Millisecond {
		t.Fatalf("stats min=%s avg=%s max=%s", p.Min(), p.Average(), p.Max())
	}
}

func TestProbeRounds(t *testing.T) {
	if got := probeRounds(59); got != 10 {
		t.Fatalf("59 attempts = %d rounds, want 10", got)
	}
	if got := probeRounds(3); got != 1 {
		t.Fatalf("3 attempts = %d rounds, want 1", got)
	}
}

func TestSlowestMaxSkipsFailures(t *testing.T) {
	probes := []ProbeResult{
		{Phase: "reachability", Samples: []time.Duration{100 * time.Millisecond}},
		{Phase: "reachability", Samples: []time.Duration{400 * time.Millisecond}, Err: errSample},
		{Phase: "catalog", Samples: []time.Duration{250 * time.Millisecond, 350 * time.Millisecond}},
	}
	if got := slowestMax(probes, "reachability"); got != 100*time.Millisecond {
		t.Fatalf("reachability = %s", got)
	}
	if got := slowestMax(probes, "catalog"); got != 350*time.Millisecond {
		t.Fatalf("catalog = %s", got)
	}
}

var errSample = errString("fail")

type errString string

func (e errString) Error() string { return string(e) }

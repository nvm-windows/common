package http

import (
	"common/settings"
	"fmt"
	"io"
	"strings"
	"time"
)

// ProbeResult is one URL measured count times.
type ProbeResult struct {
	Phase   string
	URL     string
	Samples []time.Duration
	Err     error
}

func (p ProbeResult) Min() time.Duration {
	return extreme(p.Samples, true)
}

func (p ProbeResult) Max() time.Duration {
	return extreme(p.Samples, false)
}

func (p ProbeResult) Average() time.Duration {
	if len(p.Samples) == 0 {
		return 0
	}
	var sum time.Duration
	for _, s := range p.Samples {
		sum += s
	}
	return sum / time.Duration(len(p.Samples))
}

func extreme(samples []time.Duration, min bool) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	out := samples[0]
	for _, s := range samples[1:] {
		if min && s < out {
			out = s
		}
		if !min && s > out {
			out = s
		}
	}
	return out
}

// Measurement is a doctor deadline probe of the configured mirrors.
type Measurement struct {
	Probes   []ProbeResult
	Failed   bool
	Reach    time.Duration
	Manifest time.Duration
}

// MeasureDownloadSources times HEAD index.tab, npm /-/ping, and GET index.tab.
// Each attempt uses budget. A failed attempt marks the measurement failed.
func MeasureDownloadSources(count int, budget time.Duration) Measurement {
	if count < 1 {
		count = 3
	}
	if budget <= 0 {
		budget = time.Duration(settings.DefaultTimeoutDownloadMs) * time.Millisecond
	}
	cfg := settings.Global()
	var out Measurement
	for _, mirror := range cfg.NodeMirror {
		base := strings.TrimRight(strings.TrimSpace(mirror), "/")
		if base == "" {
			continue
		}
		index := base + "/index.tab"
		out.Probes = append(out.Probes, probeMany("reachability", "HEAD", index, count, budget))
		out.Probes = append(out.Probes, probeMany("catalog", "GET", index, count, budget))
	}
	for _, mirror := range cfg.NpmMirror {
		base := strings.TrimRight(strings.TrimSpace(mirror), "/")
		if base == "" {
			continue
		}
		out.Probes = append(out.Probes, probeMany("reachability", "GET", base+"/-/ping", count, budget))
	}
	out.Reach = slowestAverage(out.Probes, "reachability")
	out.Manifest = slowestAverage(out.Probes, "catalog")
	for _, p := range out.Probes {
		if p.Err != nil {
			out.Failed = true
			break
		}
	}
	return out
}

func slowestAverage(probes []ProbeResult, phase string) time.Duration {
	var slowest time.Duration
	for _, p := range probes {
		if p.Phase != phase || p.Err != nil || len(p.Samples) == 0 {
			continue
		}
		if avg := p.Average(); avg > slowest {
			slowest = avg
		}
	}
	return slowest
}

func probeMany(phase, method, url string, count int, budget time.Duration) ProbeResult {
	result := ProbeResult{Phase: phase, URL: url}
	client := NewClient(budget)
	for i := 0; i < count; i++ {
		elapsed, err := probeOnce(client, method, url)
		if err != nil {
			result.Err = err
			return result
		}
		result.Samples = append(result.Samples, elapsed)
	}
	return result
}

func probeOnce(client *Client, method, url string) (time.Duration, error) {
	start := time.Now()
	var err error
	var status int
	if method == "HEAD" {
		res, headErr := client.Head(url)
		err = headErr
		if res != nil {
			status = res.StatusCode
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
	} else {
		res, getErr := client.Get(url)
		err = getErr
		if res != nil {
			status = res.StatusCode
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
	}
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, err
	}
	if status < 200 || status >= 400 {
		return elapsed, fmt.Errorf("HTTP %d", status)
	}
	return elapsed, nil
}

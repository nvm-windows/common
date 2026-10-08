package http

import (
	"common/settings"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// probeParallelism is how many attempts run at once.
// Each attempt has its own TCP connection, so six do not queue on one socket.
// 59 attempts then finish in about 10 rounds.
const probeParallelism = 6

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
// Reach and Manifest are the slowest successful sample in that phase.
type Measurement struct {
	Probes   []ProbeResult
	Failed   bool
	Reach    time.Duration
	Manifest time.Duration
}

// ProbeProgress reports one finished round. err is set when an attempt in that round failed.
type ProbeProgress func(phase, url string, round, rounds int, err error)

// MeasureDownloadSources times HEAD index.tab, npm /-/ping, and GET index.tab.
// Each attempt uses budget. A failed attempt marks the measurement failed.
// progress may be nil. It is called after each round of attempts, and when an attempt fails.
func MeasureDownloadSources(count int, budget time.Duration, progress ProbeProgress) Measurement {
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
		out.Probes = append(out.Probes, probeMany("reachability", "HEAD", index, count, budget, progress))
		out.Probes = append(out.Probes, probeMany("catalog", "GET", index, count, budget, progress))
	}
	for _, mirror := range cfg.NpmMirror {
		base := strings.TrimRight(strings.TrimSpace(mirror), "/")
		if base == "" {
			continue
		}
		out.Probes = append(out.Probes, probeMany("reachability", "GET", base+"/-/ping", count, budget, progress))
	}
	out.Reach = slowestMax(out.Probes, "reachability")
	out.Manifest = slowestMax(out.Probes, "catalog")
	for _, p := range out.Probes {
		if p.Err != nil {
			out.Failed = true
			break
		}
	}
	return out
}

func slowestMax(probes []ProbeResult, phase string) time.Duration {
	var slowest time.Duration
	for _, p := range probes {
		if p.Phase != phase || p.Err != nil || len(p.Samples) == 0 {
			continue
		}
		if max := p.Max(); max > slowest {
			slowest = max
		}
	}
	return slowest
}

func probeRounds(count int) int {
	if count < 1 {
		return 0
	}
	return (count + probeParallelism - 1) / probeParallelism
}

func probeMany(phase, method, url string, count int, budget time.Duration, progress ProbeProgress) ProbeResult {
	result := ProbeResult{Phase: phase, URL: url, Samples: make([]time.Duration, count)}
	client := newProbeClient(budget)
	rounds := probeRounds(count)
	var wg sync.WaitGroup
	sem := make(chan struct{}, probeParallelism)
	var mu sync.Mutex
	var firstErr error
	completed := 0
	for i := 0; i < count; i++ {
		mu.Lock()
		failed := firstErr != nil
		mu.Unlock()
		if failed {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			elapsed, err := probeOnce(client, method, url)
			mu.Lock()
			defer mu.Unlock()
			completed++
			round := (completed + probeParallelism - 1) / probeParallelism
			waveDone := completed%probeParallelism == 0 || completed == count
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				if progress != nil {
					progress(phase, url, round, rounds, err)
				}
				return
			}
			result.Samples[i] = elapsed
			if progress != nil && waveDone && firstErr == nil {
				progress(phase, url, round, rounds, nil)
			}
		}(i)
	}
	wg.Wait()
	if firstErr != nil {
		result.Err = firstErr
		result.Samples = nil
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

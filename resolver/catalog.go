package resolver

import (
	"common/http"
	"common/settings"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// catalogOverallBudget caps all mirror attempts for one index.tab resolve.
	catalogOverallBudget = 3 * time.Second
	// catalogPerMirrorCap is the max time any single mirror may consume.
	catalogPerMirrorCap = 800 * time.Millisecond
	// catalogPerMirrorFloor keeps tiny per-mirror slices usable under fair share.
	catalogPerMirrorFloor = 200 * time.Millisecond
	// catalogCacheTTL: fresher than this → serve disk/memory cache with no network.
	catalogCacheTTL = time.Hour
)

var (
	catalogMemMu   sync.Mutex
	catalogMemBody []byte
	catalogMemAt   time.Time
)

func List(majors ...string) ([][]string, error) {
	filter, err := majorFilter(majors...)
	if err != nil {
		return nil, err
	}

	mirrors := settings.Global().NodeMirror
	if len(mirrors) == 0 {
		return nil, fmt.Errorf("no Node.js mirrors configured")
	}

	// Process-local memo: avoid repeat disk/network within TTL.
	if body, ok := catalogMemory(); ok {
		return parseIndexTab(body, filter), nil
	}

	// Cache-first: newest on-disk index.tab across configured mirrors.
	staleBody, staleMod, hasStale := loadNewestCachedIndex(mirrors)
	if hasStale && time.Since(staleMod) < catalogCacheTTL {
		setCatalogMemory(staleBody)
		return parseIndexTab(staleBody, filter), nil
	}

	body, err := fetchIndexTab(mirrors)
	if err != nil {
		if hasStale {
			setCatalogMemory(staleBody)
			return parseIndexTab(staleBody, filter), nil
		}
		return nil, err
	}

	setCatalogMemory(body)
	return parseIndexTab(body, filter), nil
}

func majorFilter(majors ...string) (map[string]bool, error) {
	if len(majors) == 0 {
		return nil, nil
	}
	filter := make(map[string]bool, len(majors))
	for _, m := range majors {
		v := strings.Split(strings.TrimPrefix(m, "v"), ".")[0]
		if _, err := strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("invalid major version: %s", m)
		}
		filter[v] = true
	}
	return filter, nil
}

func catalogMemory() ([]byte, bool) {
	catalogMemMu.Lock()
	defer catalogMemMu.Unlock()
	if len(catalogMemBody) == 0 || time.Since(catalogMemAt) >= catalogCacheTTL {
		return nil, false
	}
	out := make([]byte, len(catalogMemBody))
	copy(out, catalogMemBody)
	return out, true
}

func setCatalogMemory(body []byte) {
	catalogMemMu.Lock()
	defer catalogMemMu.Unlock()
	catalogMemBody = append([]byte(nil), body...)
	catalogMemAt = time.Now()
}

func loadNewestCachedIndex(mirrors []string) (body []byte, mod time.Time, ok bool) {
	for _, mirror := range mirrors {
		url := strings.TrimRight(strings.TrimSpace(mirror), "/") + "/index.tab"
		content, _, mtime, found := http.FindCachedForURL(url)
		if !found {
			continue
		}
		if !ok || mtime.After(mod) {
			body = content
			mod = mtime
			ok = true
		}
	}
	return body, mod, ok
}

func perMirrorBudget(mirrorsLeft int, remaining time.Duration) time.Duration {
	if remaining <= 0 || mirrorsLeft <= 0 {
		return 0
	}
	fair := remaining / time.Duration(mirrorsLeft)
	budget := catalogPerMirrorCap
	if fair < budget {
		budget = fair
	}
	if budget < catalogPerMirrorFloor {
		if catalogPerMirrorFloor <= remaining {
			budget = catalogPerMirrorFloor
		} else {
			budget = remaining
		}
	}
	if budget > remaining {
		budget = remaining
	}
	return budget
}

func fetchIndexTab(mirrors []string) ([]byte, error) {
	deadline := time.Now().Add(catalogOverallBudget)
	var lastErr error

	for i, mirror := range mirrors {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		mirrorBudget := perMirrorBudget(len(mirrors)-i, remaining)
		if mirrorBudget <= 0 {
			break
		}

		url := strings.TrimRight(strings.TrimSpace(mirror), "/") + "/index.tab"
		job, err := http.Download(url, http.DownloadConfig{
			Cache:   true,
			Timeout: mirrorBudget,
		})
		if err != nil {
			lastErr = err
			continue
		}

		res, err := job.Wait()
		if err != nil {
			lastErr = err
			continue
		}
		if res == nil || !res.Success || len(res.Content) == 0 {
			lastErr = fmt.Errorf("empty or unsuccessful response from %s", mirror)
			continue
		}

		return res.Content, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to fetch version manifests from any server (budget %s): %v", catalogOverallBudget, lastErr)
	}
	return nil, fmt.Errorf("failed to fetch version manifests from any server: %s", strings.Join(mirrors, ", "))
}

func parseIndexTab(content []byte, filter map[string]bool) [][]string {
	versions := [][]string{}
	rows := strings.Split(string(content), "\n")
	headerSkipped := false
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row == "" {
			continue
		}

		if !headerSkipped {
			headerSkipped = true
			continue
		}

		cols := strings.Split(row, "\t")
		if len(cols) < 11 {
			continue
		}

		version := strings.TrimPrefix(strings.TrimSpace(cols[0]), "v")
		major := strings.Split(version, ".")[0]
		if filter != nil {
			if _, ok := filter[major]; !ok {
				continue
			}
		}

		releaseDate := strings.TrimSpace(cols[1])
		npmVersion := strings.TrimPrefix(strings.TrimSpace(cols[3]), "v")
		lts := strings.TrimPrefix(strings.TrimSpace(cols[9]), "-")
		security := strings.TrimPrefix(strings.TrimSpace(cols[10]), "-")

		versions = append(versions, []string{version, releaseDate, npmVersion, lts, security})
	}
	return versions
}

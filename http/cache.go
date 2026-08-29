package http

import (
	"common/fs"
	"common/settings"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var httpCacheRoot = "http"

type cacheWriteCloser struct {
	body io.ReadCloser
	file *os.File
	path string

	complete bool
}

func (c *cacheWriteCloser) Read(p []byte) (int, error) {
	n, err := c.body.Read(p)

	if n > 0 {
		if _, writeErr := c.file.Write(p[:n]); writeErr != nil {
			_ = c.file.Close()
			_ = c.body.Close()
			_ = os.Remove(c.path)
			return n, writeErr
		}
	}

	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			_ = os.Remove(c.path)
			return n, err
		}

		if errors.Is(err, io.EOF) {
			c.complete = true
		}

		_ = c.file.Close()
	}

	return n, err
}

func (c *cacheWriteCloser) Close() error {
	err := c.body.Close()
	if c.file != nil {
		_ = c.file.Close()
	}

	if !c.complete {
		_ = os.Remove(c.path)
	}

	return err
}

func getCacheFilePath(rawURL, etag string) (string, error) {
	normalizedURL, err := normalizeURL(rawURL)
	if err != nil {
		return "", err
	}

	cacheDir, err := GetCacheDir()
	if err != nil {
		return "", err
	}

	name := sanitizeFileName(normalizedURL + "__" + etag)
	return filepath.Join(cacheDir, name), nil
}

// FindCachedForURL returns the newest on-disk cache entry for a URL (any ETag).
// Used for cache-first reads and If-None-Match / 304 handling without a network round-trip.
func FindCachedForURL(rawURL string) (content []byte, etag string, modTime time.Time, ok bool) {
	cacheDir, err := GetCacheDir()
	if err != nil {
		return nil, "", time.Time{}, false
	}
	return findCachedForURLIn(cacheDir, rawURL)
}

func findCachedForURLIn(cacheDir, rawURL string) (content []byte, etag string, modTime time.Time, ok bool) {
	normalizedURL, err := normalizeURL(rawURL)
	if err != nil {
		return nil, "", time.Time{}, false
	}

	prefix := sanitizeFileName(normalizedURL + "__")
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, "", time.Time{}, false
	}

	var bestPath string
	var bestMod time.Time
	var bestEtag string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if bestPath != "" && !info.ModTime().After(bestMod) {
			continue
		}
		bestPath = filepath.Join(cacheDir, name)
		bestMod = info.ModTime()
		bestEtag = strings.TrimPrefix(name, prefix)
	}

	if bestPath == "" {
		return nil, "", time.Time{}, false
	}

	data, err := os.ReadFile(bestPath)
	if err != nil || len(data) == 0 {
		return nil, "", time.Time{}, false
	}

	return data, bestEtag, bestMod, true
}

// pruneURLCacheEntries removes stale cache files for a URL and keeps only keepPath.
// This prevents old ETag variants from accumulating in the cache directory.
func pruneURLCacheEntries(rawURL, keepPath string) error {
	normalizedURL, err := normalizeURL(rawURL)
	if err != nil {
		return err
	}

	cacheDir, err := GetCacheDir()
	if err != nil {
		return err
	}

	prefix := sanitizeFileName(normalizedURL + "__")
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		fullPath := filepath.Join(cacheDir, name)
		if strings.EqualFold(fullPath, keepPath) {
			continue
		}
		_ = os.Remove(fullPath)
	}

	return nil
}

func GetCacheDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	cacheDir := cacheDirPath(exe, settings.Global().Root)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}

	fs.HideDirectory(filepath.Dir(cacheDir))
	fs.HideDirectory(cacheDir)

	return cacheDir, nil
}

func cacheDirPath(executablePath, installRoot string) string {
	installRoot = settings.Expand(strings.TrimSpace(installRoot))
	if installRoot != "" {
		return filepath.Join(filepath.Dir(filepath.Clean(installRoot)), ".cache", httpCacheRoot)
	}

	return filepath.Join(filepath.Dir(executablePath), ".cache", httpCacheRoot)
}

func normalizeEtag(value string) string {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(v, "W/")
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"")
	return v
}

func sanitizeFileName(name string) string {
	if name == "" {
		return "unknown"
	}

	replacer := strings.NewReplacer(
		"<", "_",
		">", "_",
		":", "_",
		"\"", "_",
		"/", "_",
		"\\", "_",
		"|", "_",
		"?", "_",
		"*", "_",
	)

	return replacer.Replace(name)
}

package http

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
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

	cacheDir := filepath.Join(filepath.Dir(exe), ".cache", httpCacheRoot)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}

	// Hide the cache directory on Windows
	cacheDirUTF16, err := windows.UTF16PtrFromString(cacheDir)
	if err != nil {
		return "", err
	}

	// FILE_ATTRIBUTE_HIDDEN = 0x02
	const FILE_ATTRIBUTE_HIDDEN = 0x02
	_ = windows.SetFileAttributes(cacheDirUTF16, FILE_ATTRIBUTE_HIDDEN)

	return cacheDir, nil
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

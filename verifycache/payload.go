package verifycache

import (
	"common/settings"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

const cacheSchemaVersion = uint32(1)
const archiveCacheSchemaVersion = uint32(2)

func normalizeNodePath(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(strings.TrimSpace(path)))
	if err != nil {
		return "", fmt.Errorf("failed to normalize node path: %w", err)
	}
	return abs, nil
}

func cacheKeyForPath(path string) (string, error) {
	normalized, err := normalizeNodePath(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.ToLower(normalized)))
	return hex.EncodeToString(sum[:]), nil
}

func canonicalPayload(path string, size int64, mtime uint64, thumbprint string) (string, error) {
	normalized, err := normalizeNodePath(path)
	if err != nil {
		return "", err
	}

	lines := []string{
		"v1",
		strings.ToLower(normalized),
		strconv.FormatInt(size, 10),
		strconv.FormatUint(mtime, 10),
		strings.ToUpper(strings.TrimSpace(thumbprint)),
	}
	return strings.Join(lines, "\n"), nil
}

func canonicalArchivePayload(path string, size int64, mtime uint64, digest string) (string, error) {
	normalized, err := normalizeNodePath(path)
	if err != nil {
		return "", err
	}

	lines := []string{
		"v2-archive",
		strings.ToLower(normalized),
		strconv.FormatInt(size, 10),
		strconv.FormatUint(mtime, 10),
		strings.ToLower(strings.TrimSpace(digest)),
	}
	return strings.Join(lines, "\n"), nil
}

func dataRootFromSettings() (string, error) {
	installRoot := strings.TrimSpace(settings.Global().Root)
	if installRoot == "" {
		return "", fmt.Errorf("install root is not configured")
	}
	dataRoot := filepath.Dir(filepath.Clean(installRoot))
	if dataRoot == "" || dataRoot == "." {
		return "", fmt.Errorf("unable to resolve data root from install root %q", installRoot)
	}
	return dataRoot, nil
}

func dataRootFromNodePath(nodeExePath string) (string, error) {
	installDir := filepath.Dir(nodeExePath)
	installRoot := filepath.Dir(installDir)
	dataRoot := filepath.Dir(installRoot)
	if strings.TrimSpace(dataRoot) == "" || dataRoot == "." {
		return "", fmt.Errorf("unable to resolve data root from %s", nodeExePath)
	}
	return dataRoot, nil
}

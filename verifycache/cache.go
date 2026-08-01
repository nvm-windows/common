//go:build windows

package verifycache

import (
	"common/registry"
	"common/settings"
	"common/verify"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	prefs "common/preferences"
)

const verifyCacheRootSuffix = "/VerifyCache"

// SignNodeCache verifies nodeExePath and writes a TPM-signed HKCU cache entry.
func SignNodeCache(nodeExePath string) error {
	return SignNodeCacheWithSigners(nodeExePath, verify.EffectiveAllowedSigners(settings.Global().AllowedSigners))
}

// SignNodeCacheWithSigners is the explicit-signer variant for tests.
func SignNodeCacheWithSigners(nodeExePath string, allowedSigners []string) error {
	nodeExePath = strings.TrimSpace(nodeExePath)
	if nodeExePath == "" {
		return fmt.Errorf("node executable path is empty")
	}

	dataRoot, err := dataRootFromNodePath(nodeExePath)
	if err != nil {
		return err
	}

	if err := EnsureVerifyKey(dataRoot); err != nil {
		return err
	}

	if _, err := verify.VerifyNodeExecutable(nodeExePath, allowedSigners); err != nil {
		return err
	}

	size, mtime, err := nodeFileTimes(nodeExePath)
	if err != nil {
		return err
	}

	thumbprint := verify.SignerThumbprint(nodeExePath)
	if thumbprint == "" {
		return fmt.Errorf("unable to resolve signer thumbprint for %s", filepath.Base(nodeExePath))
	}

	payload, err := canonicalPayload(nodeExePath, size, mtime, thumbprint)
	if err != nil {
		return err
	}

	containerName, err := loadKeyContainerName(dataRoot)
	if err != nil {
		return err
	}

	key, err := openPersistedKey(containerName)
	if err != nil {
		return err
	}
	defer key.Close()

	signature, err := signPayload(key, []byte(payload))
	if err != nil {
		return err
	}

	normalizedPath, err := normalizeNodePath(nodeExePath)
	if err != nil {
		return err
	}

	cacheKey, err := cacheKeyForPath(nodeExePath)
	if err != nil {
		return err
	}

	base := cacheEntryRoot(cacheKey)
	if err := registry.Put(normalizedPath, base+"/Path"); err != nil {
		return err
	}
	if err := registry.Put(uint64(size), base+"/Size"); err != nil {
		return err
	}
	if err := registry.Put(mtime, base+"/Mtime"); err != nil {
		return err
	}
	if err := registry.Put(thumbprint, base+"/Thumbprint"); err != nil {
		return err
	}
	if err := registry.Put(signature, base+"/Sig"); err != nil {
		return err
	}
	if err := registry.Put(cacheSchemaVersion, base+"/Version"); err != nil {
		return err
	}

	return nil
}

func signNodeCache(nodeExePath string, allowedSigners []string) error {
	return SignNodeCacheWithSigners(nodeExePath, allowedSigners)
}

// ClearNodeCache removes the HKCU cache entry for nodeExePath.
func ClearNodeCache(nodeExePath string) error {
	return clearNodeCache(nodeExePath)
}

func clearNodeCache(nodeExePath string) error {
	cacheKey, err := cacheKeyForPath(nodeExePath)
	if err != nil {
		return err
	}
	return deleteRegistrySubKey(cacheEntryRoot(cacheKey))
}

// ClearAllCache removes all HKCU verify-cache entries for the current profile.
func ClearAllCache() error {
	return clearAllCache()
}

func clearAllCache() error {
	root := cacheRoot()
	keys, err := registry.GetSubKeys(root)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if strings.EqualFold(key, downloadCacheBucket) {
			if err := clearDownloadArchiveCacheAll(); err != nil {
				return err
			}
			continue
		}
		if err := deleteRegistrySubKey(root + "/" + key); err != nil {
			return err
		}
	}
	return nil
}

// PrewarmVerifyCache signs the active node.exe and optionally every installed version.
func PrewarmVerifyCache(allInstalled bool) error {
	return prewarmVerifyCache(allInstalled, settings.Global().AllowedSigners)
}

func prewarmVerifyCache(allInstalled bool, allowedSigners []string) error {
	installRoot := strings.TrimSpace(settings.Global().Root)
	if installRoot == "" {
		return nil
	}

	targets, err := prewarmTargets(installRoot, allInstalled)
	if err != nil {
		return err
	}

	var firstErr error
	for _, target := range targets {
		if err := signNodeCache(target, allowedSigners); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func prewarmTargets(installRoot string, allInstalled bool) ([]string, error) {
	if allInstalled {
		matches, err := filepath.Glob(filepath.Join(installRoot, "v*", "node.exe"))
		if err != nil {
			return nil, err
		}
		return matches, nil
	}

	active := strings.TrimSpace(settings.Global().ActiveVersion)
	if active == "" {
		active = strings.TrimSpace(settings.Global().LastVersion)
	}
	if active == "" {
		return nil, nil
	}
	active = strings.TrimPrefix(strings.ToLower(active), "v")
	nodePath := filepath.Join(installRoot, "v"+active, "node.exe")
	if _, err := os.Stat(nodePath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return []string{nodePath}, nil
}

func cacheRoot() string {
	return strings.TrimRight(strings.TrimSpace(prefs.ROOT), "/") + verifyCacheRootSuffix
}

func cacheEntryRoot(cacheKey string) string {
	return cacheRoot() + "/" + cacheKey
}

func readCacheEntry(cacheKey string) (map[string]interface{}, error) {
	return registry.GetAll(cacheEntryRoot(cacheKey))
}

func verifyStoredSignature(dataRoot, cacheKey string, entry map[string]interface{}) error {
	sig, ok := entry["Sig"].([]byte)
	if !ok || len(sig) == 0 {
		return fmt.Errorf("cache signature missing")
	}

	pathValue, _ := entry["Path"].(string)
	sizeValue := entryUint64(entry["Size"])
	mtimeValue := entryUint64(entry["Mtime"])
	thumbprintValue, _ := entry["Thumbprint"].(string)

	payload, err := canonicalPayload(pathValue, int64(sizeValue), mtimeValue, thumbprintValue)
	if err != nil {
		return err
	}

	containerName, err := loadKeyContainerName(dataRoot)
	if err != nil {
		return err
	}

	key, err := openPersistedKey(containerName)
	if err != nil {
		return err
	}
	defer key.Close()

	return verifySignatureWithKey(key, []byte(payload), sig)
}

func hashPayload(payload []byte) [32]byte {
	return sha256.Sum256(payload)
}

func entryUint64(value interface{}) uint64 {
	switch v := value.(type) {
	case uint64:
		return v
	case uint32:
		return uint64(v)
	case int64:
		if v > 0 {
			return uint64(v)
		}
	case int:
		if v > 0 {
			return uint64(v)
		}
	case string:
		return 0
	}
	return 0
}

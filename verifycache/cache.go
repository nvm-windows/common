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

	// Hot path: unchanged node.exe with a valid TPM cache entry skips WinVerifyTrust.
	if err := verifyNodeCache(dataRoot, nodeExePath, allowedSigners); err == nil {
		return nil
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

	digest, err := fileSHA256(nodeExePath)
	if err != nil {
		return fmt.Errorf("unable to hash %s: %w", filepath.Base(nodeExePath), err)
	}
	securityState, err := nodeFileSecurityState(nodeExePath)
	if err != nil {
		return fmt.Errorf("unable to read security state for %s: %w", filepath.Base(nodeExePath), err)
	}

	payload, err := canonicalPayload(nodeExePath, size, mtime, thumbprint, digest, securityState)
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
	if err := registry.Put(digest, base+"/Digest"); err != nil {
		return err
	}
	if err := registry.Put(securityState.VolumeSerial, base+"/VolumeSerial"); err != nil {
		return err
	}
	if err := registry.Put(securityState.FileID, base+"/FileID"); err != nil {
		return err
	}
	if err := registry.Put(securityState.USN, base+"/USN"); err != nil {
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
		if strings.EqualFold(key, scriptCacheBucket) {
			if err := clearScriptCacheAll(); err != nil {
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
		versionDir := filepath.Dir(target)
		if err := SignVersionScripts(versionDir); err != nil && firstErr == nil {
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

func verifyNodeCache(dataRoot, nodeExePath string, allowedSigners []string) error {
	nodeExePath = strings.TrimSpace(nodeExePath)
	if nodeExePath == "" {
		return fmt.Errorf("node executable path is empty")
	}

	size, mtime, err := nodeFileTimes(nodeExePath)
	if err != nil {
		return err
	}

	digest, err := fileSHA256(nodeExePath)
	if err != nil {
		return fmt.Errorf("unable to hash %s: %w", filepath.Base(nodeExePath), err)
	}

	securityState, err := nodeFileSecurityState(nodeExePath)
	if err != nil {
		return fmt.Errorf("unable to read security state for %s: %w", filepath.Base(nodeExePath), err)
	}

	cacheKey, err := cacheKeyForPath(nodeExePath)
	if err != nil {
		return err
	}

	entry, err := readCacheEntry(cacheKey)
	if err != nil {
		return err
	}
	if len(entry) == 0 {
		return fmt.Errorf("node cache entry missing")
	}

	version := uint32(entryUint64(entry["Version"]))
	if version != cacheSchemaVersion {
		return fmt.Errorf("unsupported node cache schema version %d", version)
	}

	pathValue, _ := entry["Path"].(string)
	normalizedPath, err := normalizeNodePath(nodeExePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(pathValue), normalizedPath) {
		return fmt.Errorf("node cache path mismatch")
	}

	if int64(entryUint64(entry["Size"])) != size {
		return fmt.Errorf("node cache size mismatch")
	}
	if entryUint64(entry["Mtime"]) != mtime {
		return fmt.Errorf("node cache modification time mismatch")
	}
	if entry["VolumeSerial"] == nil || entry["FileID"] == nil || entry["USN"] == nil {
		return fmt.Errorf("node cache file security state missing")
	}
	if uint32(entryUint64(entry["VolumeSerial"])) != securityState.VolumeSerial ||
		entryUint64(entry["FileID"]) != securityState.FileID ||
		entryUint64(entry["USN"]) != securityState.USN {
		return fmt.Errorf("node cache file identity mismatch")
	}

	storedDigest, _ := entry["Digest"].(string)
	if !strings.EqualFold(strings.TrimSpace(storedDigest), digest) {
		return fmt.Errorf("node cache digest mismatch")
	}

	storedThumbprint, _ := entry["Thumbprint"].(string)
	liveThumbprint := verify.SignerThumbprint(nodeExePath)
	if strings.TrimSpace(storedThumbprint) == "" || liveThumbprint == "" {
		return fmt.Errorf("node cache thumbprint missing")
	}
	if !strings.EqualFold(strings.TrimSpace(storedThumbprint), liveThumbprint) {
		return fmt.Errorf("node cache thumbprint mismatch")
	}

	signer := verify.SignerOrganization(nodeExePath)
	if !verify.IsAllowedSigner(signer, verify.EffectiveAllowedSigners(allowedSigners)) {
		return fmt.Errorf("node cache signer %q is not allowed", signer)
	}
	if !verify.IsAllowedThumbprint(liveThumbprint, settings.Global().AllowedThumbprints) {
		return fmt.Errorf("node cache thumbprint is not pinned")
	}

	if err := verifyStoredSignature(dataRoot, cacheKey, entry); err != nil {
		return fmt.Errorf("node cache signature invalid: %w", err)
	}

	return nil
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
	digestValue, _ := entry["Digest"].(string)
	if strings.TrimSpace(digestValue) == "" {
		return fmt.Errorf("cache digest missing")
	}
	if entry["VolumeSerial"] == nil || entry["FileID"] == nil || entry["USN"] == nil {
		return fmt.Errorf("cache file security state missing")
	}
	securityState := fileSecurityState{
		VolumeSerial: uint32(entryUint64(entry["VolumeSerial"])),
		FileID:       entryUint64(entry["FileID"]),
		USN:          entryUint64(entry["USN"]),
	}

	payload, err := canonicalPayload(pathValue, int64(sizeValue), mtimeValue, thumbprintValue, digestValue, securityState)
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

//go:build windows

package verifycache

import (
	"common/registry"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const scriptCacheBucket = "scripts"

// ErrScriptCacheMiss indicates no TPM-signed script trust entry exists.
var ErrScriptCacheMiss = errors.New("delegated script cache entry missing")

// SignVersionScripts records TPM-signed hashes for top-level .cmd/.bat launchers,
// package-manager JS entrypoints (npm-cli.js / npx-cli.js), and Authenticode
// verify-cache entries for top-level .exe helpers.
func SignVersionScripts(versionDir string) error {
	dataRoot, err := dataRootFromVersionDir(versionDir)
	if err != nil {
		return err
	}
	return signVersionScripts(dataRoot, versionDir)
}

func signVersionScripts(dataRoot, versionDir string) error {
	versionDir = filepath.Clean(strings.TrimSpace(versionDir))
	if versionDir == "" {
		return fmt.Errorf("version directory is empty")
	}

	entries, err := os.ReadDir(versionDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if err := EnsureVerifyKey(dataRoot); err != nil {
		return err
	}

	var firstErr error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		path := filepath.Join(versionDir, name)
		switch ext {
		case ".cmd", ".bat":
			if err := signDelegatedScript(dataRoot, path); err != nil && firstErr == nil {
				firstErr = err
			}
		case ".exe":
			// node.exe is also signed by SignNodeCache; signing again is idempotent.
			if err := SignNodeCache(path); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	for _, rel := range packageManagerCliRelPaths() {
		cliPath := filepath.Join(versionDir, filepath.FromSlash(rel))
		if _, err := os.Stat(cliPath); err != nil {
			continue
		}
		if err := signDelegatedScript(dataRoot, cliPath); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func packageManagerCliRelPaths() []string {
	return []string{
		"node_modules/npm/bin/npm-cli.js",
		"node_modules/npm/bin/npx-cli.js",
		"node_modules/corepack/dist/corepack.js",
	}
}

func signDelegatedScript(dataRoot, scriptPath string) error {
	scriptPath = strings.TrimSpace(scriptPath)
	if scriptPath == "" {
		return fmt.Errorf("script path is empty")
	}

	size, mtime, err := nodeFileTimes(scriptPath)
	if err != nil {
		return fmt.Errorf("unable to stat script: %w", err)
	}

	digest, err := fileSHA256(scriptPath)
	if err != nil {
		return fmt.Errorf("unable to hash script: %w", err)
	}

	securityState, err := nodeFileSecurityState(scriptPath)
	if err != nil {
		return fmt.Errorf("unable to read script security state: %w", err)
	}

	payload, err := canonicalScriptPayload(scriptPath, size, mtime, digest, securityState)
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

	normalizedPath, err := normalizeNodePath(scriptPath)
	if err != nil {
		return err
	}

	cacheKey, err := cacheKeyForPath(scriptPath)
	if err != nil {
		return err
	}

	base := scriptCacheEntryRoot(cacheKey)
	if err := registry.Put(normalizedPath, base+"/Path"); err != nil {
		return err
	}
	if err := registry.Put(uint64(size), base+"/Size"); err != nil {
		return err
	}
	if err := registry.Put(mtime, base+"/Mtime"); err != nil {
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
	if err := registry.Put(scriptCacheSchemaVersion, base+"/Version"); err != nil {
		return err
	}

	return nil
}

// VerifyDelegatedScript checks digest, identity, and TPM signature for a .cmd/.bat launcher.
func VerifyDelegatedScript(scriptPath string) error {
	dataRoot, err := dataRootFromSettings()
	if err != nil {
		// Fall back to deriving from the script path (installs/vX/script.cmd).
		dataRoot, err = dataRootFromVersionDir(filepath.Dir(scriptPath))
		if err != nil {
			return err
		}
	}
	return verifyDelegatedScript(dataRoot, scriptPath)
}

func verifyDelegatedScript(dataRoot, scriptPath string) error {
	scriptPath = strings.TrimSpace(scriptPath)
	if scriptPath == "" {
		return fmt.Errorf("script path is empty")
	}

	size, mtime, err := nodeFileTimes(scriptPath)
	if err != nil {
		return fmt.Errorf("unable to stat script: %w", err)
	}

	digest, err := fileSHA256(scriptPath)
	if err != nil {
		return fmt.Errorf("unable to hash script: %w", err)
	}

	securityState, err := nodeFileSecurityState(scriptPath)
	if err != nil {
		return fmt.Errorf("unable to read script security state: %w", err)
	}

	cacheKey, err := cacheKeyForPath(scriptPath)
	if err != nil {
		return err
	}

	entry, err := readScriptCacheEntry(cacheKey)
	if err != nil {
		return err
	}
	if len(entry) == 0 {
		return ErrScriptCacheMiss
	}

	version := uint32(entryUint64(entry["Version"]))
	if version != scriptCacheSchemaVersion {
		return fmt.Errorf("unsupported script cache schema version %d", version)
	}

	pathValue, _ := entry["Path"].(string)
	normalizedPath, err := normalizeNodePath(scriptPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(pathValue), normalizedPath) {
		return fmt.Errorf("script cache path mismatch")
	}

	if int64(entryUint64(entry["Size"])) != size {
		return fmt.Errorf("script cache size mismatch")
	}
	if entryUint64(entry["Mtime"]) != mtime {
		return fmt.Errorf("script cache modification time mismatch")
	}
	if entry["VolumeSerial"] == nil || entry["FileID"] == nil || entry["USN"] == nil {
		return fmt.Errorf("script cache file security state missing")
	}
	if uint32(entryUint64(entry["VolumeSerial"])) != securityState.VolumeSerial ||
		entryUint64(entry["FileID"]) != securityState.FileID ||
		entryUint64(entry["USN"]) != securityState.USN {
		return fmt.Errorf("script cache file identity mismatch")
	}

	storedDigest, _ := entry["Digest"].(string)
	if !strings.EqualFold(strings.TrimSpace(storedDigest), digest) {
		return fmt.Errorf("script cache digest mismatch")
	}

	if err := verifyStoredScriptSignature(dataRoot, entry); err != nil {
		return fmt.Errorf("script cache signature invalid: %w", err)
	}

	return nil
}

func verifyStoredScriptSignature(dataRoot string, entry map[string]interface{}) error {
	sig, ok := entry["Sig"].([]byte)
	if !ok || len(sig) == 0 {
		return fmt.Errorf("cache signature missing")
	}

	pathValue, _ := entry["Path"].(string)
	sizeValue := entryUint64(entry["Size"])
	mtimeValue := entryUint64(entry["Mtime"])
	digestValue, _ := entry["Digest"].(string)
	securityState := fileSecurityState{
		VolumeSerial: uint32(entryUint64(entry["VolumeSerial"])),
		FileID:       entryUint64(entry["FileID"]),
		USN:          entryUint64(entry["USN"]),
	}

	payload, err := canonicalScriptPayload(pathValue, int64(sizeValue), mtimeValue, digestValue, securityState)
	if err != nil {
		return err
	}

	pubKey, err := loadTrustedPublicKey(dataRoot)
	if err != nil {
		return err
	}

	return verifyCacheSignature(pubKey, []byte(payload), sig)
}

func dataRootFromVersionDir(versionDir string) (string, error) {
	versionDir = filepath.Clean(strings.TrimSpace(versionDir))
	installRoot := filepath.Dir(versionDir)
	dataRoot := filepath.Dir(installRoot)
	if strings.TrimSpace(dataRoot) == "" || dataRoot == "." {
		return "", fmt.Errorf("unable to resolve data root from %s", versionDir)
	}
	return dataRoot, nil
}

func scriptCacheRoot() string {
	return cacheRoot() + "/" + scriptCacheBucket
}

func scriptCacheEntryRoot(cacheKey string) string {
	return scriptCacheRoot() + "/" + cacheKey
}

func readScriptCacheEntry(cacheKey string) (map[string]interface{}, error) {
	return registry.GetAll(scriptCacheEntryRoot(cacheKey))
}

func clearScriptCacheAll() error {
	root := scriptCacheRoot()
	keys, err := registry.GetSubKeys(root)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := deleteRegistrySubKey(root + "/" + key); err != nil {
			return err
		}
	}
	return nil
}

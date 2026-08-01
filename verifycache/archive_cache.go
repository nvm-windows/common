//go:build windows

package verifycache

import (
	"common/registry"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const downloadCacheBucket = "download"

// ErrDownloadCacheMiss indicates no TPM-signed download cache entry exists for the archive.
var ErrDownloadCacheMiss = errors.New("download archive cache entry missing")

// SignDownloadArchiveCache records a TPM signature for a verified Node.js .7z archive.
func SignDownloadArchiveCache(archivePath string) error {
	dataRoot, err := dataRootFromSettings()
	if err != nil {
		return err
	}
	return signDownloadArchiveCache(dataRoot, archivePath)
}

func signDownloadArchiveCache(dataRoot, archivePath string) error {
	archivePath = strings.TrimSpace(archivePath)
	if archivePath == "" {
		return fmt.Errorf("archive path is empty")
	}

	if err := EnsureVerifyKey(dataRoot); err != nil {
		return err
	}

	size, mtime, err := nodeFileTimes(archivePath)
	if err != nil {
		return fmt.Errorf("unable to stat archive: %w", err)
	}

	digest, err := fileSHA256Hex(archivePath)
	if err != nil {
		return fmt.Errorf("unable to hash archive: %w", err)
	}

	payload, err := canonicalArchivePayload(archivePath, size, mtime, digest)
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

	normalizedPath, err := normalizeNodePath(archivePath)
	if err != nil {
		return err
	}

	cacheKey, err := cacheKeyForPath(archivePath)
	if err != nil {
		return err
	}

	base := downloadCacheEntryRoot(cacheKey)
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
	if err := registry.Put(signature, base+"/Sig"); err != nil {
		return err
	}
	if err := registry.Put(archiveCacheSchemaVersion, base+"/Version"); err != nil {
		return err
	}

	return nil
}

// VerifyDownloadArchiveCache checks stat, digest, and TPM signature for archivePath.
func VerifyDownloadArchiveCache(archivePath string) error {
	dataRoot, err := dataRootFromSettings()
	if err != nil {
		return err
	}
	return verifyDownloadArchiveCache(dataRoot, archivePath)
}

func verifyDownloadArchiveCache(dataRoot, archivePath string) error {
	archivePath = strings.TrimSpace(archivePath)
	if archivePath == "" {
		return fmt.Errorf("archive path is empty")
	}

	size, mtime, err := nodeFileTimes(archivePath)
	if err != nil {
		return fmt.Errorf("unable to stat archive: %w", err)
	}

	digest, err := fileSHA256Hex(archivePath)
	if err != nil {
		return fmt.Errorf("unable to hash archive: %w", err)
	}

	cacheKey, err := cacheKeyForPath(archivePath)
	if err != nil {
		return err
	}

	entry, err := readDownloadCacheEntry(cacheKey)
	if err != nil {
		return err
	}
	if len(entry) == 0 {
		return ErrDownloadCacheMiss
	}

	version := uint32(entryUint64(entry["Version"]))
	if version != archiveCacheSchemaVersion {
		return fmt.Errorf("unsupported download cache schema version %d", version)
	}

	pathValue, _ := entry["Path"].(string)
	normalizedPath, err := normalizeNodePath(archivePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(pathValue), normalizedPath) {
		return fmt.Errorf("download cache path mismatch")
	}

	if int64(entryUint64(entry["Size"])) != size {
		return fmt.Errorf("download cache size mismatch")
	}
	if entryUint64(entry["Mtime"]) != mtime {
		return fmt.Errorf("download cache modification time mismatch")
	}

	storedDigest, _ := entry["Digest"].(string)
	if !strings.EqualFold(strings.TrimSpace(storedDigest), digest) {
		return fmt.Errorf("download cache digest mismatch")
	}

	if err := verifyStoredArchiveSignature(dataRoot, entry); err != nil {
		return fmt.Errorf("download cache signature invalid: %w", err)
	}

	return nil
}

// ClearDownloadArchiveCache removes the HKCU download-cache entry for archivePath.
func ClearDownloadArchiveCache(archivePath string) error {
	cacheKey, err := cacheKeyForPath(archivePath)
	if err != nil {
		return err
	}
	return deleteRegistrySubKey(downloadCacheEntryRoot(cacheKey))
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func downloadCacheRoot() string {
	return cacheRoot() + "/" + downloadCacheBucket
}

func downloadCacheEntryRoot(cacheKey string) string {
	return downloadCacheRoot() + "/" + cacheKey
}

func readDownloadCacheEntry(cacheKey string) (map[string]interface{}, error) {
	return registry.GetAll(downloadCacheEntryRoot(cacheKey))
}

func verifyStoredArchiveSignature(dataRoot string, entry map[string]interface{}) error {
	sig, ok := entry["Sig"].([]byte)
	if !ok || len(sig) == 0 {
		return fmt.Errorf("cache signature missing")
	}

	pathValue, _ := entry["Path"].(string)
	sizeValue := entryUint64(entry["Size"])
	mtimeValue := entryUint64(entry["Mtime"])
	digestValue, _ := entry["Digest"].(string)

	payload, err := canonicalArchivePayload(pathValue, int64(sizeValue), mtimeValue, digestValue)
	if err != nil {
		return err
	}

	pubKey, err := os.ReadFile(PubKeyPath(dataRoot))
	if err != nil {
		return err
	}

	return verifyCacheSignature(pubKey, []byte(payload), sig)
}

func clearDownloadArchiveCacheAll() error {
	root := downloadCacheRoot()
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

//go:build windows

package verifycache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"common/fs"
)

// EnsureVerifyKey creates {dataRoot}/.verify, provisions an NCrypt signing key
// when needed, and exports the public key to pubkey.cer plus pubkey.sha256 (DI-01 C).
//
// .verify always receives a protected DACL (DI-01 D). When the on-disk pubkey no
// longer matches the NCrypt-exported blob, HKCU verify-cache entries are wiped.
func EnsureVerifyKey(dataRoot string) error {
	dataRoot = filepath.Clean(strings.TrimSpace(dataRoot))
	if dataRoot == "" || dataRoot == "." {
		return fmt.Errorf("data root is empty")
	}

	verifyDir := Dir(dataRoot)
	if err := os.MkdirAll(verifyDir, 0o755); err != nil {
		return fmt.Errorf("failed to create verify directory: %w", err)
	}
	_ = fs.HideDirectory(verifyDir)
	if err := fs.HardenVerifyDirectory(verifyDir); err != nil {
		return fmt.Errorf("failed to harden verify directory: %w", err)
	}

	containerName, err := loadKeyContainerName(dataRoot)
	if err != nil {
		return err
	}

	pubKeyPath := PubKeyPath(dataRoot)
	if _, err := os.Stat(pubKeyPath); err == nil {
		return rebindOrValidatePubKey(dataRoot, containerName)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect public key: %w", err)
	}

	key, providerName, err := provisionKey(containerName)
	if err != nil {
		return err
	}
	defer key.Close()

	if err := exportPublicKey(key, pubKeyPath); err != nil {
		return err
	}

	if err := saveKeyContainerName(dataRoot, containerName, providerName); err != nil {
		return err
	}

	return nil
}

func rebindOrValidatePubKey(dataRoot, containerName string) error {
	diskBlob, err := os.ReadFile(PubKeyPath(dataRoot))
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	if err := assertPubKeyFingerprint(dataRoot, diskBlob); err == nil {
		return nil
	}

	key, err := openPersistedKey(containerName)
	if err != nil {
		key2, providerName, provErr := provisionKey(containerName)
		if provErr != nil {
			return fmt.Errorf("public key fingerprint mismatch and key open failed: %v / %w", err, provErr)
		}
		defer key2.Close()
		_ = invalidateAllVerifyCacheEntries()
		if err := exportPublicKey(key2, PubKeyPath(dataRoot)); err != nil {
			return err
		}
		return saveKeyContainerName(dataRoot, containerName, providerName)
	}
	defer key.Close()

	exported, err := exportECCPublicBlob(key.handle)
	if err != nil {
		return err
	}

	if !bytes.Equal(exported, diskBlob) {
		_ = invalidateAllVerifyCacheEntries()
		return exportPublicKey(key, PubKeyPath(dataRoot))
	}

	// Same NCrypt blob; repair missing/stale fingerprint only.
	return writePubKeyFingerprint(dataRoot, diskBlob)
}

func writePubKeyFingerprint(dataRoot string, pubKeyBlob []byte) error {
	sum := sha256.Sum256(pubKeyBlob)
	hexDigest := hex.EncodeToString(sum[:])
	path := PubKeyFingerprintPath(dataRoot)
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(hexDigest+"\n"), 0o644); err != nil {
		return fmt.Errorf("failed to write temporary pubkey fingerprint: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("failed to install pubkey fingerprint: %w", err)
	}
	return nil
}

func assertPubKeyFingerprint(dataRoot string, pubKeyBlob []byte) error {
	raw, err := os.ReadFile(PubKeyFingerprintPath(dataRoot))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("pubkey fingerprint missing")
		}
		return err
	}
	want := strings.ToLower(strings.TrimSpace(string(raw)))
	sum := sha256.Sum256(pubKeyBlob)
	got := hex.EncodeToString(sum[:])
	if want != got {
		return fmt.Errorf("pubkey fingerprint mismatch")
	}
	return nil
}

// loadTrustedPublicKey loads pubkey.cer only when its SHA-256 matches pubkey.sha256.
func loadTrustedPublicKey(dataRoot string) ([]byte, error) {
	blob, err := os.ReadFile(PubKeyPath(dataRoot))
	if err != nil {
		return nil, err
	}
	if err := assertPubKeyFingerprint(dataRoot, blob); err != nil {
		return nil, err
	}
	return blob, nil
}

func loadKeyContainerName(dataRoot string) (string, error) {
	path := KeyContainerPath(dataRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultKeyName, nil
		}
		return "", fmt.Errorf("failed to read key container file: %w", err)
	}

	name := strings.TrimSpace(string(data))
	if name == "" {
		return defaultKeyName, nil
	}

	// key-container.txt format: first line = key name, optional second line = provider.
	if idx := strings.IndexByte(name, '\n'); idx >= 0 {
		name = strings.TrimSpace(name[:idx])
	}
	if name == "" {
		return defaultKeyName, nil
	}
	return name, nil
}

func saveKeyContainerName(dataRoot, keyName, providerName string) error {
	content := strings.TrimSpace(keyName)
	if strings.TrimSpace(providerName) != "" {
		content += "\n" + strings.TrimSpace(providerName)
	}
	return os.WriteFile(KeyContainerPath(dataRoot), []byte(content), 0o644)
}

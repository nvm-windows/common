package verifycache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"common/fs"
)

// EnsureVerifyKey creates {dataRoot}/.verify, provisions an NCrypt signing key
// when needed, and exports the public key to pubkey.cer.
//
// When pubkey.cer already exists, this returns immediately without opening NCrypt.
// Stale or missing backing keys are repaired when signing runs (SignNodeCache).
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

	containerName, err := loadKeyContainerName(dataRoot)
	if err != nil {
		return err
	}

	pubKeyPath := PubKeyPath(dataRoot)
	if _, err := os.Stat(pubKeyPath); err == nil {
		return nil
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

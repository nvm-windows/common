//go:build windows

package verifycache

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"common/registry"
	"common/system"
)

// Status summarizes runtime verify-cache health for a data root.
type Status struct {
	DataRoot            string
	PubKeyPath          string
	PubKeyPresent       bool
	KeyContainerPresent bool
	CacheEntryCount     int
	CachedPaths         []string
	Degraded            bool
	VerifyKeyName       string
	VerifyKeyOpen       bool
}

// CollectStatus inspects pubkey material and HKCU verify-cache entries.
func CollectStatus(dataRoot string) (Status, error) {
	dataRoot = filepath.Clean(strings.TrimSpace(dataRoot))
	if dataRoot == "" || dataRoot == "." {
		return Status{}, fmt.Errorf("data root is empty")
	}

	status := Status{
		DataRoot:   dataRoot,
		PubKeyPath: PubKeyPath(dataRoot),
	}

	if _, err := os.Stat(status.PubKeyPath); err == nil {
		status.PubKeyPresent = true
	} else if !os.IsNotExist(err) {
		return status, fmt.Errorf("failed to inspect public key: %w", err)
	}

	if _, err := os.Stat(KeyContainerPath(dataRoot)); err == nil {
		status.KeyContainerPresent = true
	}

	keys, err := registry.GetSubKeys(cacheRoot())
	if err == nil {
		status.CacheEntryCount = len(keys)
		for _, key := range keys {
			entry, readErr := readCacheEntry(key)
			if readErr != nil {
				continue
			}
			if pathValue, ok := entry["Path"].(string); ok && strings.TrimSpace(pathValue) != "" {
				status.CachedPaths = append(status.CachedPaths, pathValue)
			}
		}
	}

	status.Degraded = !status.PubKeyPresent

	keyName, err := loadKeyContainerName(dataRoot)
	if err != nil {
		return status, err
	}
	status.VerifyKeyName = keyName
	key, err := openPersistedKey(keyName)
	if err == nil {
		status.VerifyKeyOpen = true
		key.Close()
	}
	return status, nil
}

// RepairForDoctor recreates missing pubkey material and re-signs every
// installed Node version, including package-manager entrypoints left unsigned
// by a 2.0.0 upgrade.
func RepairForDoctor(dataRoot string) error {
	if err := EnsureVerifyKey(dataRoot); err != nil {
		return err
	}
	return PrewarmVerifyCache(true)
}

// WriteDoctorReport prints verify-cache status for nvm doctor.
func WriteDoctorReport(w io.Writer, status Status) {
	fmt.Fprintln(w, "Verify cache")
	fmt.Fprintf(w, "  Pubkey     : %s\n", pubkeyDoctorLine(status))
	fmt.Fprintf(w, "  HKCU cache : %d %s\n", status.CacheEntryCount, cacheRegistryLine())
	for _, path := range status.CachedPaths {
		fmt.Fprintf(w, "    - %s\n", path)
	}
	fmt.Fprintf(w, "  Mode       : %s\n", modeDoctorLine(status))
	if !status.VerifyKeyOpen {
		name := strings.TrimSpace(status.VerifyKeyName)
		if name == "" {
			name = defaultKeyName
		}
		fmt.Fprintf(w, "  Verify key : missing (%s)\n", name)
		fmt.Fprintf(w, "  Note       : %s\n", verifyKeyDoctorNote())
	}
}

func verifyKeyDoctorNote() string {
	label := system.AntivirusLabel()
	if label == system.AntivirusNotDetected {
		return "Security software may lock this key store during npm upgrade. Event code: NVM4312"
	}
	verb := "is"
	if strings.Contains(label, ",") {
		verb = "are"
	}
	return label + " " + verb + " installed and may lock this key store during npm upgrade. Event code: NVM4312"
}

func pubkeyDoctorLine(status Status) string {
	if status.PubKeyPresent {
		return "present (" + status.PubKeyPath + ")"
	}
	return "missing (" + status.PubKeyPath + ")"
}

func cacheRegistryLine() string {
	return "entries at " + strings.ReplaceAll(cacheRoot(), "/", `\`)
}

func modeDoctorLine(status Status) string {
	if status.Degraded {
		return "degraded (full Authenticode verify on each spawn)"
	}
	if status.CacheEntryCount == 0 {
		return "accelerated key ready; cache empty until install/use/reshim"
	}
	return "accelerated (pubkey + HKCU cache)"
}

//go:build windows

package verifycache

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// invalidateAllVerifyCacheEntries removes HKCU VerifyCache tree so forged
// entries cannot survive a pubkey/NCrypt identity change (DI-01).
func invalidateAllVerifyCacheEntries() error {
	root := cacheRoot()
	return deleteRegistryTree(root)
}

func deleteRegistryTree(registryPath string) error {
	hive, remainder, err := parseRegistryPath(registryPath)
	if err != nil {
		return err
	}
	if remainder == "" {
		return nil
	}

	key, err := registry.OpenKey(hive, remainder, registry.ALL_ACCESS)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return fmt.Errorf("open verify cache root: %w", err)
	}

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		key.Close()
		return err
	}
	for _, name := range subkeys {
		if err := deleteRegistryTree(registryPath + `\` + name); err != nil {
			key.Close()
			return err
		}
	}
	key.Close()

	return deleteRegistrySubKey(registryPath)
}

package resolver

import (
	"common/settings"
	"os"
	"path/filepath"
)

func IsInstalled(version string) (bool, string, error) {
	// Fast path: exact x.y.z version present on disk — no network needed.
	if v, ok := CheckInstalledLocally(version); ok {
		return true, v, nil
	}

	// Fast path: partial spec matching an installed version — no network needed.
	if v, ok := LatestInstalledMatch(version); ok {
		return true, v, nil
	}

	// Slow path: resolve via network (handles aliases like lts, latest, user aliases).
	v, _, err := Find(version)
	if err != nil {
		return false, v, err
	}

	path, err := settings.Get("root")
	if err != nil {
		return false, v, err
	}

	installPath := filepath.Join(settings.Expand(path.(string)), "v"+v)
	nodePath := filepath.Join(installPath, "node.exe")
	if _, err := os.Stat(nodePath); os.IsNotExist(err) {
		return false, v, nil
	} else if err != nil {
		return false, v, err
	}

	return true, v, nil
}

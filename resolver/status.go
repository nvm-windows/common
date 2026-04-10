package resolver

import (
	"common/settings"
	"os"
	"path/filepath"
)

func IsInstalled(version string) (bool, string, error) {
	v, _, err := Find(version)
	if err != nil {
		return false, v, err
	}

	path, err := settings.Get("root")
	if err != nil {
		return false, v, err
	}

	installPath := filepath.Join(settings.Expand(path.(string)), "v"+v)
	if _, err := os.Stat(installPath); os.IsNotExist(err) {
		return false, v, nil
	}

	return true, v, nil
}

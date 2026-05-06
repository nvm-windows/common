package resolver

import (
	"common/settings"
	"os"
	"path/filepath"
)

var (
	checkInstalledLocallyFn = CheckInstalledLocally
	latestInstalledMatchFn  = LatestInstalledMatch
	findVersionFn           = Find
	isInstalledFn           = IsInstalled
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

// ResolveInstalledVersion resolves a requested version into the concrete
// version that should be used, plus whether that version is already installed.
// When resolvePartialRemotely is true, partial version specs are resolved
// against the remote catalog before checking whether the concrete version is
// installed locally. When false, partial version specs are matched only
// against installed versions and never fall through to remote resolution.
func ResolveInstalledVersion(requestedVersion string, resolvePartialRemotely bool) (bool, string, error) {
	if resolvePartialRemotely && isPartialVersionSpec(requestedVersion) {
		version, _, err := findVersionFn(requestedVersion)
		if err != nil {
			return false, "", err
		}
		if v, ok := checkInstalledLocallyFn(version); ok {
			return true, v, nil
		}
		return false, version, nil
	}

	if latest, ok := latestInstalledMatchFn(requestedVersion); ok {
		return true, latest, nil
	}
	if v, ok := checkInstalledLocallyFn(requestedVersion); ok {
		return true, v, nil
	}
	if !resolvePartialRemotely && isPartialVersionSpec(requestedVersion) {
		return false, requestedVersion, nil
	}

	return isInstalledFn(requestedVersion)
}

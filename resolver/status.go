package resolver

import (
	"common/settings"
	"os"
	"path/filepath"
	"strings"
)

var (
	checkInstalledLocallyFn = CheckInstalledLocally
	latestInstalledMatchFn  = LatestInstalledMatch
	findVersionFn           = Find
	isInstalledFn           = IsInstalled
	resolveLocalOnlyAliasFn = resolveLocalOnlyAlias
)

func IsInstalled(version string) (bool, string, error) {
	// Expand local aliases before any network work.
	for depth := 0; depth < 8; depth++ {
		concrete, ok := resolveLocalOnlyAliasFn(version)
		if !ok || strings.EqualFold(strings.TrimSpace(concrete), strings.TrimSpace(version)) {
			break
		}
		version = concrete
	}

	// Fast path: exact x.y.z version present on disk — no network needed.
	if v, ok := CheckInstalledLocally(version); ok {
		return true, v, nil
	}

	// Fast path: partial spec matching an installed version — no network needed.
	if v, ok := LatestInstalledMatch(version); ok {
		return true, v, nil
	}

	// Slow path: resolve via network (handles aliases like lts, latest).
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
	return resolveInstalledVersion(requestedVersion, resolvePartialRemotely, 0)
}

func resolveInstalledVersion(requestedVersion string, resolvePartialRemotely bool, depth int) (bool, string, error) {
	// Expand user/default/current aliases locally so `nvm use <alias>` does not
	// wait on a remote index.tab fetch when the target is already known.
	if depth < 8 {
		if concrete, ok := resolveLocalOnlyAliasFn(requestedVersion); ok {
			if !strings.EqualFold(strings.TrimSpace(concrete), strings.TrimSpace(requestedVersion)) {
				return resolveInstalledVersion(concrete, resolvePartialRemotely, depth+1)
			}
		}
	}

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

	if isNamedSpecifier(requestedVersion) {
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

// resolveLocalOnlyAlias maps default/current and user-defined aliases without
// touching the network. latest/lts still require the catalog via Find.
func resolveLocalOnlyAlias(version string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(version))
	if v == "" {
		return "", false
	}
	if v == "default" || v == "current" {
		active := strings.TrimSpace(settings.Global().ActiveVersion)
		if active == "" {
			return "", false
		}
		return active, true
	}
	if v == "latest" || v == "lts" || strings.HasPrefix(v, "lts/") {
		return "", false
	}

	cfg := settings.Global()
	for _, pair := range cfg.Aliases {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), strings.TrimSpace(version)) {
			target := strings.TrimSpace(parts[1])
			if target != "" {
				return target, true
			}
		}
	}
	return "", false
}

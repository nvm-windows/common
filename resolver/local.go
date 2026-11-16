package resolver

import (
	"common/settings"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// NormalizeVersion strips the leading "v" prefix, lowercases, and removes any
// prerelease/build suffix. Examples: "v18.1.0-rc.1" → "18.1.0", "V22" → "22".
func NormalizeVersion(version string) string {
	v := strings.TrimSpace(version)
	v = strings.TrimPrefix(strings.ToLower(v), "v")
	return strings.Split(v, "-")[0]
}

// CanonicalVersion strips a leading "v" and lowercases, but keeps prerelease
// and build metadata. Examples: "v27.0.0-alpha.0.0.0" → "27.0.0-alpha.0.0.0".
func CanonicalVersion(version string) string {
	v := strings.TrimSpace(version)
	return strings.TrimPrefix(strings.ToLower(v), "v")
}

// IsUnstableVersion reports whether version carries prerelease/build metadata
// (any '-' after the core x.y.z tag).
func IsUnstableVersion(version string) bool {
	return strings.Contains(CanonicalVersion(version), "-")
}

// IsAlphaVersion reports whether version is a Node.js alpha prerelease
// (canonical form contains "-alpha").
func IsAlphaVersion(version string) bool {
	return strings.Contains(CanonicalVersion(version), "-alpha")
}

// ScanInstalled returns all installed Node.js versions from the configured
// install root, sorted in descending semver order. Only directories that
// contain node.exe are included.
func ScanInstalled() []string {
	root := settings.Expand(settings.Global().Root)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	versions := make([]*semver.Version, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(strings.ToLower(name), "v") {
			continue
		}
		nodeExe := filepath.Join(root, name, "node.exe")
		if _, err := os.Stat(nodeExe); err != nil {
			continue
		}
		v, err := semver.NewVersion(strings.TrimPrefix(strings.ToLower(name), "v"))
		if err != nil {
			continue
		}
		versions = append(versions, v)
	}

	sort.Sort(sort.Reverse(semver.Collection(versions)))
	result := make([]string, len(versions))
	for i, v := range versions {
		result[i] = v.Original()
	}
	return result
}

// LatestInstalledMatch returns the highest installed version matching a partial
// spec (major only, e.g. "18", or major.minor, e.g. "18.1"). The second return
// value is false when no match is found or spec is not a valid partial.
//
// Non-prerelease installs always beat prereleases for the same partial spec, so
// `nvm use 27` prefers 27.0.x over 27.1.0-alpha even when the alpha is newer by
// plain semver. When no stable match exists, the newest matching prerelease is
// returned (alpha-only majors). The returned string is canonical (keeps
// prerelease tags when that is the only match).
//
// An optional pre-scanned list may be passed to avoid a redundant disk scan;
// if omitted, ScanInstalled() is called internally.
func LatestInstalledMatch(spec string, installed ...[]string) (string, bool) {
	normalized := NormalizeVersion(spec)
	parts := strings.Split(normalized, ".")
	if len(parts) == 0 || len(parts) > 2 {
		return "", false
	}
	for _, p := range parts {
		if p == "" {
			return "", false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return "", false
		}
	}

	var list []string
	if len(installed) > 0 {
		list = installed[0]
	} else {
		list = ScanInstalled()
	}
	if len(list) == 0 {
		return "", false
	}

	major := parts[0]
	minor := ""
	if len(parts) > 1 {
		minor = parts[1]
	}

	// ScanInstalled is descending semver. Prefer the first stable match; remember
	// the first prerelease as fallback when no GA exists under the partial.
	fallback := ""
	for _, version := range list {
		canonical := CanonicalVersion(version)
		core := NormalizeVersion(canonical)
		vparts := strings.Split(core, ".")
		if len(vparts) < 3 {
			continue
		}
		if vparts[0] != major {
			continue
		}
		if minor != "" && vparts[1] != minor {
			continue
		}
		if !IsUnstableVersion(canonical) {
			return canonical, true
		}
		if fallback == "" {
			fallback = canonical
		}
	}
	if fallback != "" {
		return fallback, true
	}
	return "", false
}

// LatestInstalledAlpha returns the newest installed Node.js alpha prerelease
// (canonical tag containing "-alpha"), or ("", false) when none are installed.
// Used so `alpha` stays restricted to alpha builds and never picks GA/rc.
func LatestInstalledAlpha(installed ...[]string) (string, bool) {
	var list []string
	if len(installed) > 0 {
		list = installed[0]
	} else {
		list = ScanInstalled()
	}
	for _, version := range list {
		canonical := CanonicalVersion(version)
		if IsAlphaVersion(canonical) {
			return canonical, true
		}
	}
	return "", false
}

// CheckInstalledLocally reports whether an exact x.y.z (or x.y.z-prerelease)
// version is present on disk without making any network requests. Returns
// (canonicalVersion, true) on success. Non-exact specs (partial, aliases)
// always return ("", false).
func CheckInstalledLocally(spec string) (string, bool) {
	canonical := CanonicalVersion(spec)
	core := NormalizeVersion(canonical)
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return "", false
	}
	for _, p := range parts {
		if p == "" {
			return "", false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return "", false
		}
	}

	root := settings.Expand(settings.Global().Root)
	nodeExe := filepath.Join(root, "v"+canonical, "node.exe")
	if _, err := os.Stat(nodeExe); err != nil {
		return "", false
	}
	return canonical, true
}

func isPartialVersionSpec(version string) bool {
	normalized := NormalizeVersion(version)
	parts := strings.Split(normalized, ".")
	if len(parts) == 0 || len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

func isExactVersionSpec(version string) bool {
	normalized := NormalizeVersion(version)
	parts := strings.Split(normalized, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

// isNamedSpecifier reports CLI tokens that must be resolved through Find
// (latest, lts, alpha, default, current, user aliases) rather than local-only
// partial matching.
func isNamedSpecifier(version string) bool {
	if isPartialVersionSpec(version) || isExactVersionSpec(version) {
		return false
	}
	return strings.TrimSpace(version) != ""
}

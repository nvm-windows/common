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

	// ScanInstalled returns versions in descending order, so the first match is
	// the latest installed version satisfying the spec.
	for _, version := range list {
		v := NormalizeVersion(version)
		vparts := strings.Split(v, ".")
		if len(vparts) < 3 {
			continue
		}
		if vparts[0] != major {
			continue
		}
		if minor != "" && vparts[1] != minor {
			continue
		}
		return v, true
	}

	return "", false
}

// CheckInstalledLocally reports whether an exact x.y.z version is present on
// disk without making any network requests. Returns (canonicalVersion, true) on
// success. Non-exact specs (partial, aliases) always return ("", false).
func CheckInstalledLocally(spec string) (string, bool) {
	normalized := NormalizeVersion(spec)
	parts := strings.Split(normalized, ".")
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
	nodeExe := filepath.Join(root, "v"+normalized, "node.exe")
	if _, err := os.Stat(nodeExe); err != nil {
		return "", false
	}
	return normalized, true
}

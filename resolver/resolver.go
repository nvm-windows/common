package resolver

import (
	"common/http"
	"common/settings"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	semver "github.com/Masterminds/semver/v3"
)

func List(majors ...string) ([][]string, error) {
	var filter map[string]bool
	if len(majors) > 0 {
		// Filter by major versions if specified.
		filter = make(map[string]bool, len(majors))
		for _, m := range majors {
			v := strings.Split(strings.TrimPrefix(m, "v"), ".")[0]
			_, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("invalid major version: %s", m)
			}
			filter[v] = true
		}
	}

	mirrors := settings.Global().NodeMirror
	var content []byte

	success := false
	for _, mirror := range mirrors {
		// fmt.Printf("Fetching versions from %s...\n", mirror)
		job, err := http.Download(fmt.Sprintf("%s/index.tab", mirror), http.DownloadConfig{Cache: true})
		if err != nil {
			continue
		}

		res, err := job.Wait()
		if err != nil || res == nil || !res.Success {
			continue
		}

		if res.Success {
			success = true
			content = res.Content

			break
		}
	}

	if !success {
		return nil, fmt.Errorf("failed to fetch version manifests from any server: %s", strings.Join(mirrors, ", "))
	}

	// Parse content
	versions := [][]string{}
	rows := strings.Split(string(content), "\n")
	headerSkipped := false
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row == "" {
			continue
		}

		// Skip first non-empty row (header).
		if !headerSkipped {
			headerSkipped = true
			continue
		}

		cols := strings.Split(row, "\t")
		if len(cols) < 11 {
			continue
		}

		version := strings.TrimPrefix(strings.TrimSpace(cols[0]), "v")

		// Optionally filter on major version.
		major := strings.Split(version, ".")[0]
		if filter != nil {
			if _, ok := filter[major]; !ok {
				continue
			}
		}

		releaseDate := strings.TrimSpace(cols[1])
		npmVersion := strings.TrimPrefix(strings.TrimSpace(cols[3]), "v")
		lts := strings.TrimPrefix(strings.TrimSpace(cols[9]), "-")
		security := strings.TrimPrefix(strings.TrimSpace(cols[10]), "-")

		versions = append(versions, []string{version, releaseDate, npmVersion, lts, security})
	}

	return versions, nil
}

// FindVersion returns the best matching version for a given version string, along with its npm version.
// The input version string can be a full version (e.g. "v16.13.0"), a major.minor (e.g. "16.13"), or just a major version (e.g. "16").
// Aliases "latest", "lts", and "lts/<name>" are also accepted.
// The function will attempt to find the best match based on the available versions.
func Find(version string) (string, string, error) {
	// Resolve aliases before normal version parsing.
	lower := strings.ToLower(strings.TrimSpace(version))
	if lower == "latest" || lower == "lts" || strings.HasPrefix(lower, "lts/") {
		resolved, err := alias(lower)
		if err != nil {
			return "", "", err
		}
		version = resolved
	}

	// Strip prerelease/build metadata and leading "v" for matching purposes.
	// Prereleases will not be supported until the new Node.js schedule is
	// implemented with Alpha releases.
	v := strings.Split(strings.TrimPrefix(strings.TrimSpace(version), "v"), "-")[0]
	parts := strings.Split(v, ".")

	major := parts[0]

	var minor string
	if len(parts) > 1 {
		minor = parts[1]
	}

	var patch string
	if len(parts) > 2 {
		patch = parts[2]
	}

	versions, err := List(major)
	if err != nil {
		return "", "", err
	}

	if len(versions) == 0 {
		return "", "", fmt.Errorf("version %s not found", version)
	}

	if minor != "" {
		for _, v := range versions {
			if strings.HasPrefix(v[0], major+"."+minor+".") {
				if patch == "" {
					return v[0], v[2], nil
				}
				if strings.EqualFold(v[0], major+"."+minor+"."+patch) {
					return v[0], v[2], nil
				}
			}
		}
	}

	return versions[0][0], versions[0][2], nil
}

// LTSName returns the LTS codename for the given version (e.g. "Jod", "Iron"),
// or an empty string if the version is not an LTS release or is not found.
func LTSName(version string) string {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	major := strings.Split(v, ".")[0]
	all, err := List(major)
	if err != nil {
		return ""
	}
	for _, ver := range all {
		if ver[0] == v {
			return ver[3]
		}
	}
	return ""
}

// alias resolves a named alias to a concrete version string.
// Supported aliases: "latest", "lts", "lts/<name>".
func alias(version string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(version))

	if v == "latest" {
		all, err := List()
		if err != nil {
			return "", err
		}
		if len(all) == 0 {
			return "", fmt.Errorf("no versions found")
		}
		return all[0][0], nil
	}

	if v == "lts" {
		all, err := List()
		if err != nil {
			return "", err
		}
		for _, ver := range all {
			if ver[3] != "" {
				return ver[0], nil
			}
		}
		return "", fmt.Errorf("no LTS version found")
	}

	if strings.HasPrefix(v, "lts/") {
		name := strings.TrimPrefix(v, "lts/")
		all, err := List()
		if err != nil {
			return "", err
		}
		for _, ver := range all {
			if strings.EqualFold(ver[3], name) {
				return ver[0], nil
			}
		}
		return "", fmt.Errorf("no LTS version found with name %q", name)
	}

	return "", fmt.Errorf("unknown alias: %s", version)
}

// Resolve returns the best concrete Node.js version for the given input.
// It accepts:
//   - Named aliases: "latest", "lts", "lts/<name>"
//   - Exact or partial versions: "18", "18.20", "18.20.1", "v18.20.1"
//   - Semver range constraints from package.json: "^18", ">=16", "~20.1", "*", "18.x"
func Resolve(version string) (string, error) {
	v := strings.TrimSpace(version)
	if v == "" {
		return "", fmt.Errorf("version must not be empty")
	}

	// Handle aliases and plain/partial versions via Find, which covers
	// "latest", "lts", "lts/<name>", "18", "18.20", "18.20.1", "v18.20.1".
	resolved, _, err := Find(v)
	if err == nil {
		return resolved, nil
	}

	// Treat the input as a semver constraint (e.g. "^18", ">=16.0.0", "~20.1", "*").
	c, err := semver.NewConstraint(v)
	if err != nil {
		return "", fmt.Errorf("unrecognised version or constraint %q: %w", version, err)
	}

	all, err := List(majorHint(v)...)
	if err != nil {
		return "", err
	}

	for _, ver := range all {
		sv, err := semver.NewVersion(ver[0])
		if err != nil {
			continue
		}
		if c.Check(sv) {
			return ver[0], nil
		}
	}

	return "", fmt.Errorf("no Node.js version satisfies constraint %q", version)
}

// majorHint extracts a single major version from a constraint string when the
// constraint is bounded to one major (^, ~, or N.x / N.*), so List can be
// filtered rather than fetching the full release index.
// Returns nil for open-ended constraints like ">=16", "*", or ranges.
func majorHint(constraint string) []string {
	s := strings.TrimSpace(constraint)

	// Caret (^) and tilde (~) are always bounded to the parsed major.
	if len(s) > 1 && (s[0] == '^' || s[0] == '~') {
		rest := strings.TrimSpace(s[1:])
		major := strings.Split(strings.TrimPrefix(rest, "v"), ".")[0]
		if _, err := strconv.Atoi(major); err == nil {
			return []string{major}
		}
	}

	// "18.x", "18.*", "18.x.x" — exact major wildcard.
	parts := strings.SplitN(s, ".", 2)
	if len(parts) == 2 {
		major := strings.TrimPrefix(parts[0], "v")
		tail := strings.ToLower(parts[1])
		if _, err := strconv.Atoi(major); err == nil {
			if strings.HasPrefix(tail, "x") || strings.HasPrefix(tail, "*") {
				return []string{major}
			}
		}
	}

	return nil
}

// ResolveActiveVersion determines the active Node.js version based on the current environment
// settings and returns the version.
func ResolveActiveVersion(cwd ...string) (string, error) {
	wd := ""
	if len(cwd) > 0 {
		wd = filepath.Clean(cwd[0])
	} else {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current working directory: %w", err)
		}
	}

	cfg := settings.Global()
	version := cfg.ActiveVersion

	if cfg.AutoUse && len(cfg.AutoDetect) > 0 {
		for _, file := range cfg.AutoDetect {
			file = filepath.Join(wd, file)

			if _, err := os.Stat(file); err == nil {
				if raw, err := os.ReadFile(file); err == nil {
					if strings.ToLower(filepath.Ext(file)) == ".json" {
						var data map[string]interface{}
						if err := json.Unmarshal(raw, &data); err == nil {
							switch strings.ToLower(filepath.Base(file)) {
							case "package.json":
								data = data["engines"].(map[string]interface{})
								fallthrough
							default:
								if v, ok := data["node"].(string); ok {
									if strings.TrimSpace(v) == "" {
										continue
									}
									v, _ = Resolve(v)
									if v != "" {
										version = v
										break
									}
								}
							}
						}
					} else {
						v := strings.TrimSpace(string(raw))
						if v != "" {
							v, _ = Resolve(v)
							if v != "" {
								version = v
								break
							}
						}
					}
				}
			}
		}
	}

	return version, nil
}

func Executable(version string, bin ...string) (string, error) {
	binary := "node.exe"
	if len(bin) > 0 {
		binary = bin[0]
	}

	path := filepath.Join(settings.Expand(settings.Global().Root), "v"+version, binary)

	return path, nil
}

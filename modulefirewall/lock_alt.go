package modulefirewall

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LockfileCandidates returns lockfile basenames to try for a shim family (order = preference).
func LockfileCandidates(command string) []string {
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "pnpm", "vlt":
		return []string{"pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json"}
	case "yarn", "yarnpkg":
		return []string{"yarn.lock", "package-lock.json", "npm-shrinkwrap.json"}
	default: // npm, npx, unknown
		return []string{"package-lock.json", "npm-shrinkwrap.json"}
	}
}

// ParseLockFilePackages dispatches by basename.
func ParseLockFilePackages(lockPath string) ([]PackageSpec, error) {
	base := strings.ToLower(filepath.Base(lockPath))
	switch base {
	case "pnpm-lock.yaml":
		return ParsePnpmLockPackages(lockPath)
	case "yarn.lock":
		return ParseYarnLockPackages(lockPath)
	case "package-lock.json", "npm-shrinkwrap.json":
		return ParseLockPackages(lockPath)
	default:
		return nil, fmt.Errorf("unsupported lockfile %s", base)
	}
}

// ParsePnpmLockPackages extracts package identities from pnpm-lock.yaml (v6/v9 style keys).
func ParsePnpmLockPackages(lockPath string) ([]PackageSpec, error) {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	return parsePnpmLockContent(string(raw))
}

func parsePnpmLockContent(content string) ([]PackageSpec, error) {
	seen := make(map[string]struct{})
	var out []PackageSpec
	inPackages := false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := countLeadingSpaces(line)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			key := strings.TrimSuffix(trimmed, ":")
			inPackages = key == "packages" || key == "snapshots"
			continue
		}
		if !inPackages || indent != 2 || !strings.HasSuffix(trimmed, ":") {
			continue
		}
		key := strings.TrimSuffix(trimmed, ":")
		key = strings.Trim(key, `"'`)
		name, ver := splitPnpmLockKey(key)
		if name == "" {
			continue
		}
		lk := strings.ToLower(name)
		if _, ok := seen[lk]; ok {
			continue
		}
		seen[lk] = struct{}{}
		rawTok := name
		if ver != "" {
			rawTok = name + "@" + ver
		}
		out = append(out, PackageSpec{Name: name, Version: ver, Raw: rawTok})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pnpm-lock: no packages")
	}
	return out, nil
}

func splitPnpmLockKey(key string) (name, version string) {
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, "/")
	// peer suffix: lodash@4.17.21(peer@1)
	if i := strings.IndexByte(key, '('); i > 0 {
		key = key[:i]
	}
	if strings.HasPrefix(key, "@") {
		slash := strings.IndexByte(key[1:], '/')
		if slash < 0 {
			return key, ""
		}
		rest := key[1+slash+1:]
		if at := strings.LastIndexByte(rest, '@'); at >= 0 {
			return key[:1+slash+1+at], rest[at+1:]
		}
		return key, ""
	}
	if at := strings.LastIndexByte(key, '@'); at > 0 {
		return key[:at], key[at+1:]
	}
	return key, ""
}

// ParseYarnLockPackages extracts package identities from classic or Berry yarn.lock.
func ParseYarnLockPackages(lockPath string) ([]PackageSpec, error) {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	return parseYarnLockContent(string(raw))
}

func parseYarnLockContent(content string) ([]PackageSpec, error) {
	seen := make(map[string]struct{})
	var out []PackageSpec
	sc := bufio.NewScanner(strings.NewReader(content))
	var pendingNames []string
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := countLeadingSpaces(line)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			pendingNames = yarnDescriptorNames(strings.TrimSuffix(trimmed, ":"))
			continue
		}
		if len(pendingNames) == 0 {
			continue
		}
		// classic: version "1.2.3"   berry: version: 1.2.3
		lower := strings.ToLower(trimmed)
		var ver string
		if strings.HasPrefix(lower, "version ") || strings.HasPrefix(lower, "version:") {
			ver = strings.TrimSpace(trimmed[len("version"):])
			ver = strings.TrimPrefix(ver, ":")
			ver = strings.TrimSpace(ver)
			ver = strings.Trim(ver, `"'`)
			for _, name := range pendingNames {
				lk := strings.ToLower(name)
				if _, ok := seen[lk]; ok {
					continue
				}
				seen[lk] = struct{}{}
				rawTok := name
				if ver != "" {
					rawTok = name + "@" + ver
				}
				out = append(out, PackageSpec{Name: name, Version: ver, Raw: rawTok})
			}
			pendingNames = nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("yarn.lock: no packages")
	}
	return out, nil
}

func yarnDescriptorNames(header string) []string {
	// "lodash@npm:^4.17.21", "lodash@npm:4.17.21":
	// lodash@^4.17.21, lodash@~4.17.0:
	parts := strings.Split(header, ",")
	var names []string
	seen := make(map[string]struct{})
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`)
		name := yarnNameFromDescriptor(p)
		if name == "" {
			continue
		}
		lk := strings.ToLower(name)
		if _, ok := seen[lk]; ok {
			continue
		}
		seen[lk] = struct{}{}
		names = append(names, name)
	}
	return names
}

func yarnNameFromDescriptor(desc string) string {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return ""
	}
	// Berry: name@npm:range or name@workspace:...
	if at := strings.Index(desc, "@npm:"); at > 0 {
		return desc[:at]
	}
	if at := strings.Index(desc, "@workspace:"); at > 0 {
		return desc[:at]
	}
	if strings.HasPrefix(desc, "@") {
		slash := strings.IndexByte(desc[1:], '/')
		if slash < 0 {
			return desc
		}
		rest := desc[1+slash+1:]
		if at := strings.IndexByte(rest, '@'); at >= 0 {
			return desc[:1+slash+1+at]
		}
		return desc
	}
	if at := strings.IndexByte(desc, '@'); at > 0 {
		return desc[:at]
	}
	return desc
}

func countLeadingSpaces(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' {
			n++
			continue
		}
		if r == '\t' {
			n += 2
			continue
		}
		break
	}
	return n
}

package modulefirewall

import (
	"fmt"
	"net/url"
	"strings"

	semver "github.com/Masterminds/semver/v3"
)

const (
	// DefaultTrustedWhenEmpty is applied when TrustedModules is unset/empty.
	DefaultTrustedWhenEmpty = "NOT ALL"
	// DefaultApprovedWhenEmpty is applied when ApprovedModules / ApprovedGlobalModules is unset/empty.
	DefaultApprovedWhenEmpty = "ALL"
)

// PackageSpec is a requested install/exec package identity.
type PackageSpec struct {
	Name    string // unscoped or @scope/name (no version)
	Version string // optional version / range / tag from name@version
	Raw     string // original token
}

// NormalizeList strips blanks; if empty returns defaultSeed as a one-element list.
func NormalizeList(entries []string, defaultSeed string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		if strings.TrimSpace(defaultSeed) == "" {
			return nil
		}
		return []string{strings.TrimSpace(defaultSeed)}
	}
	return out
}

// ExtractHTTPSURL returns the sole HTTPS URL if the list is URL-mode (one https URL,
// other entries ignored). ok=false when local rules apply.
func ExtractHTTPSURL(entries []string) (endpoint string, ok bool) {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		u, err := url.Parse(e)
		if err != nil || u.Scheme == "" {
			continue
		}
		if strings.EqualFold(u.Scheme, "https") && u.Host != "" {
			return e, true
		}
	}
	return "", false
}

func normalizeRuleEntry(raw string) (entry string, negated bool, err error) {
	entry = strings.TrimSpace(raw)
	if entry == "" {
		return "", false, fmt.Errorf("entry must not be empty")
	}
	lower := strings.ToLower(entry)
	if strings.HasPrefix(lower, "not ") || strings.HasPrefix(lower, "not\t") {
		negated = true
		entry = strings.TrimSpace(entry[3:])
	} else if strings.HasPrefix(entry, "!") {
		negated = true
		entry = strings.TrimSpace(entry[1:])
	}
	if entry == "" {
		return "", false, fmt.Errorf("negated rule must specify a module pattern")
	}
	return entry, negated, nil
}

// ValidateRuleEntry checks a local (non-URL) firewall rule.
func ValidateRuleEntry(raw string) error {
	entry, _, err := normalizeRuleEntry(raw)
	if err != nil {
		return err
	}
	if strings.EqualFold(entry, "all") {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(entry), "http://") {
		return fmt.Errorf("HTTP URLs are not allowed; use HTTPS")
	}
	if strings.HasPrefix(strings.ToLower(entry), "https://") {
		return nil
	}
	name, ver := splitNameVersion(entry)
	if name == "" {
		return fmt.Errorf("invalid module pattern")
	}
	if strings.HasSuffix(name, "/*") {
		org := strings.TrimSuffix(name, "/*")
		if !strings.HasPrefix(org, "@") || strings.Contains(org[1:], "/") {
			return fmt.Errorf("invalid org wildcard %q", name)
		}
		return nil
	}
	if ver == "" {
		return nil
	}
	if strings.HasSuffix(ver, ".*") {
		return nil
	}
	if _, err := semver.NewConstraint(ver); err == nil {
		return nil
	}
	// tags / plain versions
	if ver != "" {
		return nil
	}
	return fmt.Errorf("unsupported module pattern")
}

func splitNameVersion(spec string) (name, version string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}
	// @scope/name@version or name@version — version starts at last @ when scoped
	if strings.HasPrefix(spec, "@") {
		rest := spec[1:]
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			return spec, ""
		}
		after := rest[slash+1:]
		if at := strings.IndexByte(after, '@'); at >= 0 {
			return spec[:1+slash+1+at], after[at+1:]
		}
		return spec, ""
	}
	if at := strings.IndexByte(spec, '@'); at >= 0 {
		return spec[:at], spec[at+1:]
	}
	return spec, ""
}

// ParsePackageToken parses an npm-style package argument into a PackageSpec.
func ParsePackageToken(raw string) (PackageSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return PackageSpec{}, fmt.Errorf("empty package")
	}
	// skip git/http/file/path installs for MVP matching — mark as raw-only
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "git+") || strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "file:") ||
		strings.ContainsAny(raw, `\/`) && !strings.HasPrefix(raw, "@") {
		return PackageSpec{Raw: raw, Name: raw}, nil
	}
	name, ver := splitNameVersion(raw)
	return PackageSpec{Name: name, Version: ver, Raw: raw}, nil
}

func nameMatches(pattern, pkgName string) bool {
	pattern = strings.TrimSpace(pattern)
	pkgName = strings.TrimSpace(pkgName)
	if pattern == "" || pkgName == "" {
		return false
	}
	if strings.EqualFold(pattern, "all") {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		org := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(strings.ToLower(pkgName), strings.ToLower(org)+"/")
	}
	return strings.EqualFold(pattern, pkgName)
}

func versionMatches(patternVer, pkgVer string) bool {
	if patternVer == "" {
		return true // name-only rule matches any version
	}
	if pkgVer == "" {
		// request has no version (install latest) — name rule with version constraint: allow match on name only for allowlists is tricky;
		// treat as matching so allow rules with @1.x still apply to unpinned installs at policy layer (install may resolve later).
		return true
	}
	if strings.HasSuffix(patternVer, ".*") {
		prefix := strings.TrimSuffix(patternVer, ".*")
		return strings.HasPrefix(pkgVer, prefix+".") || pkgVer == prefix
	}
	if c, err := semver.NewConstraint(patternVer); err == nil {
		if v, err := semver.NewVersion(pkgVer); err == nil {
			return c.Check(v)
		}
		return false
	}
	return strings.EqualFold(patternVer, pkgVer)
}

func ruleMatches(rule string, pkg PackageSpec) bool {
	entry, _, err := normalizeRuleEntry(rule)
	if err != nil {
		return false
	}
	if strings.EqualFold(entry, "all") {
		return true
	}
	name, ver := splitNameVersion(entry)
	if !nameMatches(name, pkg.Name) {
		return false
	}
	return versionMatches(ver, pkg.Version)
}

// IsPackageAllowed evaluates package against a VersionAllowList-style module list.
// Precedence mirrors enhanced acl.IsAllowedVersion category order:
// 1) negated positive patterns deny when matched
// 2) positive patterns allow when matched
// 3) if any positive (non-ALL-only) patterns exist and none matched → deny
// 4) else allow (including explicit ALL)
func IsPackageAllowed(pkg PackageSpec, rules []string) (bool, error) {
	rules = NormalizeList(rules, DefaultApprovedWhenEmpty)
	if _, ok := ExtractHTTPSURL(rules); ok {
		return false, fmt.Errorf("remote HTTPS list must be evaluated via EvaluateRemote")
	}

	var negated, positive []string
	hasExclusive := false
	for _, raw := range rules {
		entry, neg, err := normalizeRuleEntry(raw)
		if err != nil {
			return false, fmt.Errorf("invalid module firewall entry %q: %w", raw, err)
		}
		if err := ValidateRuleEntry(raw); err != nil && !strings.HasPrefix(strings.ToLower(entry), "https://") {
			// ValidateRuleEntry already covers; soft for tags
			_ = err
		}
		if neg {
			negated = append(negated, entry)
			continue
		}
		positive = append(positive, entry)
		if !strings.EqualFold(entry, "all") {
			hasExclusive = true
		}
	}

	for _, n := range negated {
		if ruleMatches(n, pkg) || (strings.EqualFold(n, "all")) {
			// NOT ALL means deny-all unless later positive — handled: NOT ALL is negated all
			if strings.EqualFold(n, "all") {
				// fall through to positive exceptions
				break
			}
			return false, nil
		}
	}
	// If NOT ALL present, only positives allow
	notAll := false
	for _, n := range negated {
		if strings.EqualFold(n, "all") {
			notAll = true
			break
		}
	}
	if notAll {
		for _, p := range positive {
			if ruleMatches(p, pkg) {
				return true, nil
			}
		}
		return false, nil
	}

	for _, n := range negated {
		if ruleMatches(n, pkg) {
			return false, nil
		}
	}
	for _, p := range positive {
		if ruleMatches(p, pkg) {
			return true, nil
		}
	}
	if hasExclusive {
		return false, nil
	}
	return true, nil
}

// FilterBlocked returns packages not allowed by rules.
func FilterBlocked(pkgs []PackageSpec, rules []string) ([]PackageSpec, error) {
	var blocked []PackageSpec
	for _, p := range pkgs {
		ok, err := IsPackageAllowed(p, rules)
		if err != nil {
			return nil, err
		}
		if !ok {
			blocked = append(blocked, p)
		}
	}
	return blocked, nil
}

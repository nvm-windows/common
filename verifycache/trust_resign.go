//go:build windows

package verifycache

import (
	"common/modulefirewall"
	"common/settings"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// untrustedChangedSkipMessage is printed when reshim leaves a disk-changed
// untrusted launcher stale. nvm reshim alone will not persist trust.
func untrustedChangedSkipMessage(scriptPath string) string {
	name := moduleNameFromPath(scriptPath)
	return fmt.Sprintf(
		"%s changed and was not re-signed. Next launch will be blocked. nvm reshim alone will not keep this module trusted after the next self-update. To allow self-updates: nvm firewall trust module %s",
		name, name,
	)
}

func warnUntrustedChangedSkip(scriptPath string) {
	fmt.Fprintln(os.Stderr, untrustedChangedSkipMessage(scriptPath))
}

// isDiskChangeVerifyError reports whether verify failed because the on-disk
// target no longer matches a prior cache entry (content/identity drift).
func isDiskChangeVerifyError(err error) bool {
	if err == nil || errors.Is(err, ErrScriptCacheMiss) {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "entry missing") {
		return false
	}
	return strings.Contains(msg, "size mismatch") ||
		strings.Contains(msg, "modification time mismatch") ||
		strings.Contains(msg, "digest mismatch") ||
		strings.Contains(msg, "file identity mismatch")
}

func moduleNameFromPath(path string) string {
	base := filepath.Base(strings.TrimSpace(path))
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

func isAlwaysResignModule(path string) bool {
	name := strings.ToLower(moduleNameFromPath(path))
	switch name {
	case "node", "npm", "npx", "pnpm", "yarn", "yarnpkg", "corepack", "vlt":
		return true
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, rel := range packageManagerCliRelPaths() {
		if strings.HasSuffix(lower, strings.ToLower(rel)) {
			return true
		}
	}
	return false
}

// mayResignChangedModule allows resigning a disk-changed entrypoint when the
// module is trusted, UntrustedModuleHandlerAction is allow, a user-initiated
// package-manager reshim passed parent-tree authorization, or it is node/PM
// infrastructure. NVM_SIGN_CHANGED_MODULES in the environment is ignored.
func mayResignChangedModule(path string) bool {
	if isAlwaysResignModule(path) {
		return true
	}
	if allowSignChanged {
		return true
	}

	cfg := settings.Global()
	if strings.EqualFold(strings.TrimSpace(cfg.UntrustedModuleHandlerAction), "allow") {
		return true
	}

	rules := modulefirewall.NormalizeTrustedModules(cfg.TrustedModules)
	name := moduleNameFromPath(path)
	pkg := modulefirewall.PackageSpec{Name: name, Raw: name}

	// Local TrustedModules hit → allow resign without HTTP.
	if ok, err := modulefirewall.IsPackageTrustedLocal(pkg, rules); err == nil && ok {
		return true
	}

	// HTTPS URL present: query remote only for this untrusted module.
	if _, hasURL := modulefirewall.ExtractHTTPSURL(rules); hasURL {
		res := modulefirewall.EvaluateTrustedModules([]modulefirewall.PackageSpec{pkg}, rules, modulefirewall.RemoteTLSOptions{
			TimeoutSec: cfg.FirewallHTTPTimeoutSeconds,
		})
		return res.Trusted
	}
	return false
}

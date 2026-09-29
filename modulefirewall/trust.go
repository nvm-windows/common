package modulefirewall

import (
	"fmt"
	"net/http"
	"strings"
)

// evaluateRemoteRequestFn is EvaluateRemoteRequest; tests may swap it.
var evaluateRemoteRequestFn = EvaluateRemoteRequest

// TrustResult is the outcome of EvaluateTrustedModules.
type TrustResult struct {
	Trusted       bool
	RemoteQueried bool
	Remote        RemoteResult
	// Untrusted holds modules still not trusted after local+optional remote eval.
	Untrusted []PackageSpec
	// Message is a user-facing note (e.g. remote service unavailable).
	Message string
}

// StripHTTPSURLs returns list entries that are not HTTPS policy URLs.
func StripHTTPSURLs(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, ok := ExtractHTTPSURL([]string{e}); ok {
			continue
		}
		out = append(out, e)
	}
	return out
}

// IsPackageTrustedLocal evaluates TrustedModules local rules only (HTTPS URLs ignored).
func IsPackageTrustedLocal(pkg PackageSpec, trustedModules []string) (bool, error) {
	rules := NormalizeTrustedModules(trustedModules)
	local := StripHTTPSURLs(rules)
	local = NormalizeList(local, DefaultTrustedWhenEmpty)
	return isPackageAllowedLocal(pkg, local)
}

// EvaluateTrustedModules checks TrustedModules locally first. When a HTTPS URL is
// present, only modules that are not trusted locally are POSTed to that URL.
// If every module is trusted locally, no HTTP request is made.
// If HTTP is attempted and there is no usable response, modules are treated as
// untrusted and Message explains that the remote trust service is unavailable.
func EvaluateTrustedModules(pkgs []PackageSpec, trustedModules []string, opts RemoteTLSOptions) TrustResult {
	return EvaluateTrustedModulesRequest(pkgs, trustedModules, RemoteRequestOptions{RemoteTLSOptions: opts})
}

// EvaluateTrustedModulesRequest is EvaluateTrustedModules with full remote request options.
func EvaluateTrustedModulesRequest(pkgs []PackageSpec, trustedModules []string, opts RemoteRequestOptions) TrustResult {
	if len(pkgs) == 0 {
		return TrustResult{Trusted: true}
	}

	rules := NormalizeTrustedModules(trustedModules)
	endpoint, hasURL := ExtractHTTPSURL(rules)
	local := NormalizeList(StripHTTPSURLs(rules), DefaultTrustedWhenEmpty)

	var needRemote []PackageSpec
	for _, pkg := range pkgs {
		ok, err := isPackageAllowedLocal(pkg, local)
		if err != nil {
			return TrustResult{
				Trusted:   false,
				Untrusted: pkgs,
				Message:   fmt.Sprintf("trusted modules local eval failed: %v", err),
			}
		}
		if !ok {
			needRemote = append(needRemote, pkg)
		}
	}

	if len(needRemote) == 0 {
		return TrustResult{Trusted: true}
	}
	if !hasURL {
		return TrustResult{Trusted: false, Untrusted: needRemote}
	}

	res := evaluateRemoteRequestFn(endpoint, needRemote, opts)
	if !res.Allowed {
		return TrustResult{
			Trusted:       false,
			RemoteQueried: true,
			Remote:        res,
			Untrusted:     needRemote,
			Message:       FormatRemoteUserMessage(res),
		}
	}
	return TrustResult{Trusted: true, RemoteQueried: true, Remote: res}
}

func RemoteTrustUnavailable(res RemoteResult) bool {
	if res.Allowed {
		return false
	}
	// Transport / timeout / dial failures leave Status 0.
	if res.Status == 0 {
		return true
	}
	// Clear policy/auth answers from the authority — not "unavailable".
	switch res.Status {
	case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden:
		return false
	default:
		return true
	}
}

// isPackageAllowedLocal is IsPackageAllowed without HTTPS rejection (caller already stripped URLs).
func isPackageAllowedLocal(pkg PackageSpec, rules []string) (bool, error) {
	var negated, positive []string
	hasExclusive := false
	for _, raw := range rules {
		entry, neg, err := normalizeRuleEntry(raw)
		if err != nil {
			return false, fmt.Errorf("invalid module firewall entry %q: %w", raw, err)
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
		if ruleMatches(n, pkg) || strings.EqualFold(n, "all") {
			if strings.EqualFold(n, "all") {
				break
			}
			return false, nil
		}
	}
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

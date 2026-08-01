package verify

import (
	"common/settings"
	"strings"
)

// DefaultAllowedSigners re-exports the settings default for callers that cannot import settings.
var DefaultAllowedSigners = settings.DefaultAllowedSigners

// NormalizeAllowedSigners trims and drops empty signer organization names.
func NormalizeAllowedSigners(signers []string) []string {
	return normalizeAllowedSigners(signers)
}

// EffectiveAllowedSigners returns normalized signers, falling back to settings.DefaultAllowedSigners.
func EffectiveAllowedSigners(signers []string) []string {
	allowed := normalizeAllowedSigners(signers)
	if len(allowed) == 0 {
		return append([]string(nil), settings.DefaultAllowedSigners...)
	}
	return allowed
}

// IsAllowedSigner reports whether signer matches an entry in allowed (case-insensitive).
func IsAllowedSigner(signer string, allowed []string) bool {
	return isAllowedSigner(signer, allowed)
}

func normalizeAllowedSigners(signers []string) []string {
	normalized := make([]string, 0, len(signers))
	for _, signer := range signers {
		trimmed := strings.TrimSpace(signer)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func isAllowedSigner(signer string, allowed []string) bool {
	candidate := strings.TrimSpace(signer)
	if candidate == "" {
		return false
	}
	for _, allowedSigner := range allowed {
		if strings.EqualFold(candidate, strings.TrimSpace(allowedSigner)) {
			return true
		}
	}
	return false
}

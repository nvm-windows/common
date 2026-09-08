package license

import (
	"common/settings"
	"common/token"
	"strings"
)

var accessTokenForStructuredLogging = func() string {
	return strings.TrimSpace(settings.Global().AccessToken)
}

// AllowsStructuredLogging reports whether the configured access token authorizes
// structured (SIEM) event logging. Requires a non-expired audit (or legacy
// compliance) entitlement, or governance (which also unlocks SIEM). Missing/tmp/
// expired tokens and not-yet-valid tokens fall back to unstructured logging.
func AllowsStructuredLogging() bool {
	// No time-insensitive cache: exp can elapse while the same JWT is still configured.
	return licenseAllowsStructured(accessTokenForStructuredLogging())
}

func licenseAllowsStructured(raw string) bool {
	if hasCommercialEntitlement(raw, token.EntitlementAudit) {
		return true
	}
	// Governance tokens historically unlocked SIEM; keep that for array and legacy string lic.
	return hasCommercialEntitlement(raw, token.EntitlementGovernance)
}

package license

import (
	"common/settings"
	"strings"
)

var accessTokenForStructuredLogging = func() string {
	return strings.TrimSpace(settings.Global().AccessToken)
}

// AllowsStructuredLogging reports whether the configured access token authorizes
// structured (SIEM) event logging. Only a non-expired compliance (Audit) or
// governance license qualifies. Other plans, missing/tmp/expired tokens, and
// not-yet-valid tokens fall back to unstructured logging.
func AllowsStructuredLogging() bool {
	// No time-insensitive cache: exp can elapse while the same JWT is still configured.
	return licenseTypeAllowsStructured(accessTokenForStructuredLogging())
}

func licenseTypeAllowsStructured(raw string) bool {
	licenseType, ok := commercialLicenseType(raw)
	if !ok {
		return false
	}
	switch licenseType {
	case "compliance", "governance":
		return true
	default:
		return false
	}
}

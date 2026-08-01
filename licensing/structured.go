package license

import (
	"common/settings"
	"common/token"
	"strings"
	"sync"
)

var (
	structuredMu            sync.Mutex
	structuredCachedToken   string
	structuredLoggingCached bool

	accessTokenForStructuredLogging = func() string {
		return strings.TrimSpace(settings.Global().AccessToken)
	}
)

// AllowsStructuredLogging reports whether the configured access token authorizes
// structured (SIEM) event logging. Only compliance and governance licenses qualify.
// Other plans, missing tokens, and invalid tokens fall back to unstructured logging.
func AllowsStructuredLogging() bool {
	raw := accessTokenForStructuredLogging()

	structuredMu.Lock()
	defer structuredMu.Unlock()

	if raw == structuredCachedToken {
		return structuredLoggingCached
	}

	structuredCachedToken = raw
	structuredLoggingCached = licenseTypeAllowsStructured(raw)
	return structuredLoggingCached
}

func licenseTypeAllowsStructured(raw string) bool {
	if raw == "" {
		return false
	}

	parsed, err := token.ParseUnverified(raw)
	if err != nil || parsed == nil || parsed.Claims == nil {
		return false
	}

	claims, ok := parsed.Claims.(*token.TokenClaims)
	if !ok || claims == nil || claims.Tmp {
		return false
	}

	switch strings.ToLower(claims.LicenseType()) {
	case "compliance", "governance":
		return true
	default:
		return false
	}
}

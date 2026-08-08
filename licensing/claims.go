package license

import (
	"common/token"
	"strings"
	"time"
)

// FeatureGracePeriod is how long Audit/Governance features stay authorized after exp.
const FeatureGracePeriod = 7 * 24 * time.Hour

// commercialLicenseType returns the lowercase lic/plan claim when the token is a
// non-temporary commercial access token within exp + grace. Missing, invalid, tmp,
// not-yet-valid, and post-grace tokens fail. Signature is not re-checked here.
func commercialLicenseType(raw string) (string, bool) {
	claims, ok := parseCommercialClaims(raw)
	if !ok {
		return "", false
	}
	if !withinFeatureWindow(claims, time.Now()) {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(claims.LicenseType())), true
}

func parseCommercialClaims(raw string) (*token.TokenClaims, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}

	parsed, err := token.ParseUnverified(raw)
	if err != nil || parsed == nil || parsed.Claims == nil {
		return nil, false
	}

	claims, ok := parsed.Claims.(*token.TokenClaims)
	if !ok || claims == nil || claims.Tmp {
		return nil, false
	}

	licenseType := strings.ToLower(strings.TrimSpace(claims.LicenseType()))
	if licenseType == "" || licenseType == "community" {
		return nil, false
	}
	return claims, true
}

func withinFeatureWindow(claims *token.TokenClaims, now time.Time) bool {
	if claims == nil {
		return false
	}
	if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil && nbf.After(now) {
		return false
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return false
	}
	return !now.After(exp.Time.Add(FeatureGracePeriod))
}

func expirationTime(claims *token.TokenClaims) (time.Time, bool) {
	if claims == nil {
		return time.Time{}, false
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}, false
	}
	return exp.Time, true
}

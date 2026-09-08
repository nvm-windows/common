package license

import (
	"common/token"
	"strings"
	"time"
)

// FeatureGracePeriod is how long Audit/Governance features stay authorized after exp.
const FeatureGracePeriod = 7 * 24 * time.Hour

// commercialClaims returns parsed commercial claims when the token is a
// non-temporary access token with at least one commercial entitlement and is
// within exp + grace. Signature is not re-checked here.
func commercialClaims(raw string) (*token.TokenClaims, bool) {
	claims, ok := parseCommercialClaims(raw)
	if !ok {
		return nil, false
	}
	if !withinFeatureWindow(claims, time.Now()) {
		return nil, false
	}
	return claims, true
}

// commercialLicenseType returns the primary entitlement label (governance/audit/build/…).
func commercialLicenseType(raw string) (string, bool) {
	claims, ok := commercialClaims(raw)
	if !ok {
		return "", false
	}
	return claims.PrimaryEntitlement(), true
}

func hasCommercialEntitlement(raw, name string) bool {
	claims, ok := commercialClaims(raw)
	if !ok {
		return false
	}
	return claims.HasEntitlement(name)
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

	if !claimsHaveCommercialEntitlement(claims) {
		return nil, false
	}
	return claims, true
}

func claimsHaveCommercialEntitlement(claims *token.TokenClaims) bool {
	if claims == nil {
		return false
	}
	ents := claims.Entitlements()
	if len(ents) == 0 {
		return false
	}
	commercial := false
	for _, e := range ents {
		if e == token.EntitlementCommunity {
			continue
		}
		if token.IsCommercialEntitlement(e) {
			commercial = true
		}
	}
	return commercial
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

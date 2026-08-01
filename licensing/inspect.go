package license

import (
	"common/settings"
	"common/token"
	"strings"
	"time"
)

// LicenseInfo describes the configured access token for nvm env reporting.
type LicenseInfo struct {
	Plan         string
	Roles        []string
	Issued       string
	Expires      string
	Verification string
}

// InspectAccessToken loads the configured access token and optionally verifies it.
// Verification is best-effort for nvm env only; airgapped hosts may be unable to reach JWKS.
func InspectAccessToken() (LicenseInfo, bool) {
	raw := strings.TrimSpace(settings.Global().AccessToken)
	if raw == "" {
		return LicenseInfo{}, false
	}

	parsed, err := token.ParseUnverified(raw)
	if err != nil {
		return LicenseInfo{Verification: "configured, token is invalid"}, true
	}

	info := licenseInfoFromToken(parsed)
	if isCommunityLicense(parsed) {
		return info, true
	}

	if err := token.Set(raw); err != nil {
		if token.IsJWKSUnavailable(err) {
			info.Verification = "cannot verify without internet connection"
		} else {
			info.Verification = "configured, verification failed"
		}
		return info, true
	}

	if token.Access != nil {
		info = licenseInfoFromToken(token.Access)
	}
	info.Verification = "verified"
	return info, true
}

func licenseInfoFromToken(access *token.AccessToken) LicenseInfo {
	info := LicenseInfo{
		Issued:  "unknown",
		Expires: "unknown",
	}

	if access == nil || access.Claims == nil {
		return info
	}

	claims, ok := access.Claims.(*token.TokenClaims)
	if !ok {
		return info
	}

	info.Plan = claims.LicenseType()
	info.Roles = claims.Roles
	if claims.IssuedAt != nil {
		info.Issued = formatLicenseTime(claims.IssuedAt.Time)
	}
	if claims.ExpiresAt != nil {
		info.Expires = formatLicenseTime(claims.ExpiresAt.Time)
	}

	return info
}

func isCommunityLicense(access *token.AccessToken) bool {
	if access == nil || access.Claims == nil {
		return false
	}

	claims, ok := access.Claims.(*token.TokenClaims)
	if !ok {
		return false
	}

	if claims.Tmp {
		return true
	}

	return strings.EqualFold(claims.LicenseType(), "community")
}

func formatLicenseTime(value time.Time) string {
	return value.Local().Format("2006-01-02 15:04:05 MST")
}

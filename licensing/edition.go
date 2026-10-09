package license

import (
	"common/settings"
	"common/token"
	"strings"
	"unicode"
)

const (
	communityEdition        = "Community"
	certifiedEdition        = "Certified"
	certifiedInvalidLicense = "Certified: Invalid License"
)

// buildChannel is injected by qgo from the package manifest
// (common/license.buildChannel). "community" is the OSS/Inno build;
// "certified" is the MSI/enterprise package. Empty defaults to community.
var buildChannel string

var accessTokenForEdition = func() string {
	return strings.TrimSpace(settings.Global().AccessToken)
}

// IsCommunityBuild reports whether this binary is the community package
// (LocalAppData layout), independent of whether a commercial access token is set.
func IsCommunityBuild() bool {
	ch := strings.ToLower(strings.TrimSpace(buildChannel))
	return ch == "" || ch == "community"
}

// Edition returns the edition label for CLI banners. A commercial access token
// wins: build is Certified, audit is Certified Audit, governance is Certified
// Governed, and governance plus audit is Certified Governed + Audit.
// Otherwise community packages report Community. Certified packages with no
// commercial token report Certified: Invalid License.
func Edition() string {
	claims, ok := commercialClaims(accessTokenForEdition())
	if ok {
		return editionDisplay(claims)
	}
	if !IsCommunityBuild() {
		return certifiedInvalidLicense
	}
	return communityEdition
}

// editionDisplay is the banner/env name for a commercial token.
// build → Certified. audit → Certified Audit. governance → Certified Governed.
// governance and audit together → Certified Governed + Audit.
func editionDisplay(claims *token.TokenClaims) string {
	if claims == nil {
		if !IsCommunityBuild() {
			return certifiedInvalidLicense
		}
		return communityEdition
	}
	governed := claims.HasEntitlement(token.EntitlementGovernance)
	audit := claims.HasEntitlement(token.EntitlementAudit) || claims.HasEntitlement(token.EntitlementCompliance)
	switch {
	case governed && audit:
		return "Certified Governed + Audit"
	case governed:
		return "Certified Governed"
	case audit:
		return "Certified Audit"
	default:
		return certifiedEdition
	}
}

func editionLabel(licenseType string) string {
	switch strings.ToLower(strings.TrimSpace(licenseType)) {
	case token.EntitlementCompliance, token.EntitlementAudit:
		return "Certified Audit"
	case token.EntitlementGovernance:
		return "Certified Governed"
	case token.EntitlementBuild, token.EntitlementCommunity, "":
		if strings.EqualFold(strings.TrimSpace(licenseType), token.EntitlementCommunity) || strings.TrimSpace(licenseType) == "" {
			if !IsCommunityBuild() {
				return certifiedInvalidLicense
			}
			return communityEdition
		}
		return certifiedEdition
	default:
		runes := []rune(strings.ToLower(strings.TrimSpace(licenseType)))
		if len(runes) == 0 {
			if !IsCommunityBuild() {
				return certifiedInvalidLicense
			}
			return communityEdition
		}
		runes[0] = unicode.ToUpper(runes[0])
		return string(runes)
	}
}

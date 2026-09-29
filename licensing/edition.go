package license

import (
	"common/settings"
	"common/token"
	"strings"
	"unicode"
)

const (
	communityEdition = "Community"
	certifiedEdition = "Certified"
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

// Edition returns the edition label for CLI banners. Commercial entitlements
// (Governance/Audit/Distro) win when a valid access token is present.
// Otherwise community packages report Community and certified packages report
// Certified — even when operating without a paid token (community feature mode).
func Edition() string {
	licenseType, ok := commercialLicenseType(accessTokenForEdition())
	if ok {
		return editionLabel(licenseType)
	}
	if !IsCommunityBuild() {
		return certifiedEdition
	}
	return communityEdition
}

func editionLabel(licenseType string) string {
	switch strings.ToLower(strings.TrimSpace(licenseType)) {
	case token.EntitlementCompliance, token.EntitlementAudit:
		return "Audit"
	case token.EntitlementGovernance:
		return "Governance"
	case token.EntitlementBuild:
		return "Distro"
	case token.EntitlementCommunity, "":
		if !IsCommunityBuild() {
			return certifiedEdition
		}
		return communityEdition
	default:
		runes := []rune(strings.ToLower(strings.TrimSpace(licenseType)))
		if len(runes) == 0 {
			if !IsCommunityBuild() {
				return certifiedEdition
			}
			return communityEdition
		}
		runes[0] = unicode.ToUpper(runes[0])
		return string(runes)
	}
}

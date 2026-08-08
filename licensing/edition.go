package license

import (
	"common/settings"
	"strings"
	"unicode"
)

const communityEdition = "Community"

var accessTokenForEdition = func() string {
	return strings.TrimSpace(settings.Global().AccessToken)
}

// Edition returns the licensed edition label for CLI banners. The configured
// access token is parsed without contacting the licensing service so help output
// stays offline. Missing, invalid, and temporary tokens report the community edition.
func Edition() string {
	licenseType, ok := commercialLicenseType(accessTokenForEdition())
	if !ok {
		return communityEdition
	}
	return editionLabel(licenseType)
}

func editionLabel(licenseType string) string {
	switch strings.ToLower(strings.TrimSpace(licenseType)) {
	case "compliance", "audit":
		return "Audit"
	case "governance":
		return "Governance"
	case "community", "":
		return communityEdition
	default:
		runes := []rune(strings.ToLower(strings.TrimSpace(licenseType)))
		runes[0] = unicode.ToUpper(runes[0])
		return string(runes)
	}
}

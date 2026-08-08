package license

import (
	"common/settings"
	"common/token"
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
	raw := accessTokenForEdition()
	if raw == "" {
		return communityEdition
	}

	parsed, err := token.ParseUnverified(raw)
	if err != nil || parsed == nil || parsed.Claims == nil {
		return communityEdition
	}

	claims, ok := parsed.Claims.(*token.TokenClaims)
	if !ok || claims == nil || claims.Tmp {
		return communityEdition
	}

	licenseType := strings.TrimSpace(claims.LicenseType())
	if licenseType == "" {
		return communityEdition
	}

	return editionLabel(licenseType)
}

func editionLabel(licenseType string) string {
	runes := []rune(strings.ToLower(licenseType))
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

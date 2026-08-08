package license

import (
	"common/settings"
	"strings"
)

var accessTokenForAdvancedProxy = func() string {
	return strings.TrimSpace(settings.Global().AccessToken)
}

// AllowsAdvancedProxy reports whether IWA (NTLM/Negotiate/SSPI) and WinHTTP
// PAC/WPAD proxy features are authorized. Only a non-expired Governance license
// qualifies. Distro/Audit (and Community) keep basic proxy URL + basic/bearer auth.
func AllowsAdvancedProxy() bool {
	// No time-insensitive cache: exp can elapse while the same JWT is still configured.
	return licenseTypeAllowsAdvancedProxy(accessTokenForAdvancedProxy())
}

func licenseTypeAllowsAdvancedProxy(raw string) bool {
	licenseType, ok := commercialLicenseType(raw)
	return ok && licenseType == "governance"
}

package license

import (
	"common/settings"
	"common/token"
	"strings"
)

var accessTokenForAdvancedProxy = func() string {
	return strings.TrimSpace(settings.Global().AccessToken)
}

// AllowsAdvancedProxy reports whether IWA (NTLM/Negotiate/SSPI) and WinHTTP
// PAC/WPAD proxy features are authorized. Requires a non-expired governance
// entitlement. Distro/Audit (and Community) keep basic proxy URL + basic/bearer auth.
func AllowsAdvancedProxy() bool {
	// No time-insensitive cache: exp can elapse while the same JWT is still configured.
	return hasCommercialEntitlement(accessTokenForAdvancedProxy(), token.EntitlementGovernance)
}

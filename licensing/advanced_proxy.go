package license

import (
	"common/settings"
	"common/token"
)

var accessTokenForAdvancedProxy = func() string {
	return settings.PeekAccessToken()
}

// AllowsAdvancedProxy reports whether IWA (NTLM/Negotiate/SSPI) and WinHTTP
// PAC/WPAD proxy features are authorized. Same governance gate as AllowsMachinePolicy.
// Distro/Audit (and Community) keep basic proxy URL + basic/bearer auth.
func AllowsAdvancedProxy() bool {
	// Keep a dedicated token hook for tests; entitlement matches AllowsMachinePolicy.
	return hasCommercialEntitlement(accessTokenForAdvancedProxy(), token.EntitlementGovernance)
}

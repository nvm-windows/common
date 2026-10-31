package license

import (
	"common/settings"
	"common/token"
)

var accessTokenForMachinePolicy = func() string {
	// Peek — never call settings.Global() here: Load → honorMachinePolicy → this
	// would recurse forever.
	return settings.PeekAccessToken()
}

// AllowsMachinePolicy reports whether HKLM/HKCU Policies under
// Software\Policies\Author Software\nvm are honored for preference overrides,
// version/module firewall lists, and forced runtime gates.
// Requires a non-expired governance entitlement (same gate as AllowsAdvancedProxy).
// Licensing secrets (AccessToken / AccessKey / JwksCose) remain readable from
// the Policies hive so the entitlement can be established.
func AllowsMachinePolicy() bool {
	return hasCommercialEntitlement(accessTokenForMachinePolicy(), token.EntitlementGovernance)
}

package license

import (
	"common/token"
	"testing"
	"time"
)

func TestAllowsMachinePolicyGovernanceOnly(t *testing.T) {
	withMachinePolicyToken(t, mustMintAccessToken(t, "governance", false), func() {
		if !AllowsMachinePolicy() {
			t.Fatal("governance license should allow machine policy")
		}
	})
}

func TestAllowsMachinePolicyRejectsAuditAndBuild(t *testing.T) {
	withMachinePolicyToken(t, mustMintAccessTokenEntitlements(t, false, token.EntitlementAudit, token.EntitlementBuild), func() {
		if AllowsMachinePolicy() {
			t.Fatal("audit/build must not honor machine policy hive")
		}
	})
}

func TestAllowsMachinePolicyRejectsMissing(t *testing.T) {
	withMachinePolicyToken(t, "", func() {
		if AllowsMachinePolicy() {
			t.Fatal("missing token must not honor machine policy")
		}
	})
}

func TestAllowsMachinePolicyGrace(t *testing.T) {
	withMachinePolicyToken(t, mustMintAccessTokenExpiringAt(t, "governance", time.Now().Add(-time.Hour)), func() {
		if !AllowsMachinePolicy() {
			t.Fatal("governance in grace should allow machine policy")
		}
	})
	withMachinePolicyToken(t, mustMintAccessTokenExpiringAt(t, "governance", time.Now().Add(-FeatureGracePeriod-time.Hour)), func() {
		if AllowsMachinePolicy() {
			t.Fatal("governance past grace must not honor machine policy")
		}
	})
}

func withMachinePolicyToken(t *testing.T, raw string, fn func()) {
	t.Helper()
	withCommercialTrustOK(t)
	orig := accessTokenForMachinePolicy
	accessTokenForMachinePolicy = func() string { return raw }
	t.Cleanup(func() { accessTokenForMachinePolicy = orig })
	fn()
}

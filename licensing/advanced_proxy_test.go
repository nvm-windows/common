package license

import (
	"testing"
	"time"
)

func TestAllowsAdvancedProxyGovernanceOnly(t *testing.T) {
	withAdvancedProxyToken(t, mustMintAccessToken(t, "governance", false), func() {
		if !AllowsAdvancedProxy() {
			t.Fatal("governance license should allow advanced proxy")
		}
	})
}

func TestAllowsAdvancedProxyRejectsCompliance(t *testing.T) {
	withAdvancedProxyToken(t, mustMintAccessToken(t, "compliance", false), func() {
		if AllowsAdvancedProxy() {
			t.Fatal("compliance/Audit license must not allow IWA/PAC proxy")
		}
	})
}

func TestAllowsAdvancedProxyRejectsOtherPlans(t *testing.T) {
	withAdvancedProxyToken(t, mustMintAccessToken(t, "professional", false), func() {
		if AllowsAdvancedProxy() {
			t.Fatal("non-governance license must not allow advanced proxy")
		}
	})
}

func TestAllowsAdvancedProxyRejectsMissingAndTemporary(t *testing.T) {
	withAdvancedProxyToken(t, "", func() {
		if AllowsAdvancedProxy() {
			t.Fatal("missing token must not allow advanced proxy")
		}
	})
	withAdvancedProxyToken(t, mustMintAccessToken(t, "governance", true), func() {
		if AllowsAdvancedProxy() {
			t.Fatal("temporary token must not allow advanced proxy")
		}
	})
}

func TestAllowsAdvancedProxyAllowsGraceThenRejects(t *testing.T) {
	withAdvancedProxyToken(t, mustMintAccessTokenExpiringAt(t, "governance", time.Now().Add(-time.Hour)), func() {
		if !AllowsAdvancedProxy() {
			t.Fatal("governance token in 7-day grace should allow advanced proxy")
		}
	})
	withAdvancedProxyToken(t, mustMintAccessTokenExpiringAt(t, "governance", time.Now().Add(-FeatureGracePeriod-time.Hour)), func() {
		if AllowsAdvancedProxy() {
			t.Fatal("governance token past grace must not allow advanced proxy")
		}
	})
}

func withAdvancedProxyToken(t *testing.T, raw string, fn func()) {
	t.Helper()
	orig := accessTokenForAdvancedProxy
	accessTokenForAdvancedProxy = func() string { return raw }
	t.Cleanup(func() { accessTokenForAdvancedProxy = orig })
	fn()
}

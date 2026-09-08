package license

import (
	"common/token"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAllowsStructuredLoggingAuditEntitlement(t *testing.T) {
	withStructuredToken(t, mustMintAccessTokenEntitlements(t, false, token.EntitlementAudit, token.EntitlementBuild), func() {
		if !AllowsStructuredLogging() {
			t.Fatal("audit entitlement should allow structured logging")
		}
	})
}

func TestAllowsStructuredLoggingLegacyCompliance(t *testing.T) {
	withStructuredToken(t, mustMintAccessToken(t, "compliance", false), func() {
		if !AllowsStructuredLogging() {
			t.Fatal("legacy compliance license should allow structured logging")
		}
	})
}

func TestAllowsStructuredLoggingGovernance(t *testing.T) {
	withStructuredToken(t, mustMintAccessToken(t, "governance", false), func() {
		if !AllowsStructuredLogging() {
			t.Fatal("governance license should allow structured logging")
		}
	})
}

func TestAllowsStructuredLoggingBuildOnlyRejected(t *testing.T) {
	withStructuredToken(t, mustMintAccessTokenEntitlements(t, false, token.EntitlementBuild), func() {
		if AllowsStructuredLogging() {
			t.Fatal("build-only entitlement must not allow structured logging")
		}
	})
}

func TestAllowsStructuredLoggingRejectsOtherPlans(t *testing.T) {
	withStructuredToken(t, mustMintAccessToken(t, "professional", false), func() {
		if AllowsStructuredLogging() {
			t.Fatal("non-audit/governance license must not allow structured logging")
		}
	})
}

func TestAllowsStructuredLoggingRejectsMissingToken(t *testing.T) {
	withStructuredToken(t, "", func() {
		if AllowsStructuredLogging() {
			t.Fatal("missing token must not allow structured logging")
		}
	})
}

func TestAllowsStructuredLoggingRejectsTemporaryToken(t *testing.T) {
	withStructuredToken(t, mustMintAccessToken(t, "compliance", true), func() {
		if AllowsStructuredLogging() {
			t.Fatal("temporary token must not allow structured logging")
		}
	})
}

func TestAllowsStructuredLoggingGraceThenRejects(t *testing.T) {
	for _, licenseType := range []string{"compliance", "governance", "audit"} {
		t.Run(licenseType+" grace", func(t *testing.T) {
			withStructuredToken(t, mustMintAccessTokenExpiringAt(t, licenseType, time.Now().Add(-time.Hour)), func() {
				if !AllowsStructuredLogging() {
					t.Fatal("token in 7-day grace should allow structured logging")
				}
			})
		})
		t.Run(licenseType+" post-grace", func(t *testing.T) {
			withStructuredToken(t, mustMintAccessTokenExpiringAt(t, licenseType, time.Now().Add(-FeatureGracePeriod-time.Hour)), func() {
				if AllowsStructuredLogging() {
					t.Fatal("token past grace must not allow structured logging")
				}
			})
		})
	}
}

func TestLicenseTypePrefersLicClaim(t *testing.T) {
	claims := &token.TokenClaims{Lic: token.LicenseEntitlements{"compliance"}, Plan: "community"}
	if got := claims.LicenseType(); got != "compliance" {
		t.Fatalf("LicenseType() = %q, want compliance", got)
	}
}

func TestPrimaryEntitlementFromArray(t *testing.T) {
	claims := &token.TokenClaims{Lic: token.LicenseEntitlements{"audit", "build"}}
	if got := claims.PrimaryEntitlement(); got != token.EntitlementAudit {
		t.Fatalf("PrimaryEntitlement() = %q, want audit", got)
	}
	if !claims.HasEntitlement(token.EntitlementBuild) || !claims.HasEntitlement(token.EntitlementAudit) {
		t.Fatal("expected build and audit entitlements")
	}
	if claims.HasEntitlement(token.EntitlementGovernance) {
		t.Fatal("did not expect governance")
	}
}

func TestUnmarshalLicArrayAndString(t *testing.T) {
	t.Run("array", func(t *testing.T) {
		raw := mustMintAccessTokenEntitlements(t, false, token.EntitlementAudit, token.EntitlementBuild)
		parsed, err := token.ParseUnverified(raw)
		if err != nil {
			t.Fatal(err)
		}
		claims := parsed.Claims.(*token.TokenClaims)
		if !claims.HasEntitlement(token.EntitlementAudit) || !claims.HasEntitlement(token.EntitlementBuild) {
			t.Fatalf("ents = %#v", claims.Entitlements())
		}
		withStructuredToken(t, raw, func() {
			if !AllowsStructuredLogging() {
				t.Fatal("array lic with audit should allow SIEM")
			}
		})
		withAdvancedProxyToken(t, raw, func() {
			if AllowsAdvancedProxy() {
				t.Fatal("array lic without governance must not allow IWA/PAC")
			}
		})
	})
	t.Run("legacy string", func(t *testing.T) {
		raw := mustMintAccessToken(t, "governance", false)
		parsed, err := token.ParseUnverified(raw)
		if err != nil {
			t.Fatal(err)
		}
		claims := parsed.Claims.(*token.TokenClaims)
		if !claims.HasEntitlement(token.EntitlementGovernance) {
			t.Fatalf("ents = %#v", claims.Entitlements())
		}
	})
}

func withStructuredToken(t *testing.T, raw string, fn func()) {
	t.Helper()
	orig := accessTokenForStructuredLogging
	accessTokenForStructuredLogging = func() string { return raw }
	t.Cleanup(func() { accessTokenForStructuredLogging = orig })
	fn()
}

func mustMintAccessToken(t *testing.T, licenseType string, tmp bool) string {
	t.Helper()
	return mustMintAccessTokenExpiringAt(t, licenseType, time.Now().Add(time.Hour), tmp)
}

func mustMintAccessTokenEntitlements(t *testing.T, tmp bool, ents ...string) string {
	t.Helper()
	return mustMintAccessTokenEntitlementsExpiringAt(t, time.Now().Add(time.Hour), tmp, ents...)
}

func mustMintAccessTokenExpiringAt(t *testing.T, licenseType string, exp time.Time, tmp ...bool) string {
	t.Helper()
	isTmp := false
	if len(tmp) > 0 {
		isTmp = tmp[0]
	}
	return mustMintAccessTokenEntitlementsExpiringAt(t, exp, isTmp, licenseType)
}

func mustMintAccessTokenEntitlementsExpiringAt(t *testing.T, exp time.Time, tmp bool, ents ...string) string {
	t.Helper()
	now := time.Now()
	claims := &token.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Lic: token.LicenseEntitlements(ents),
		Tmp: tmp,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return raw
}

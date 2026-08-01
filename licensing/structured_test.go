package license

import (
	"common/token"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAllowsStructuredLoggingCompliance(t *testing.T) {
	withStructuredToken(t, mustMintAccessToken(t, "compliance", false), func() {
		if !AllowsStructuredLogging() {
			t.Fatal("compliance license should allow structured logging")
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

func TestAllowsStructuredLoggingRejectsOtherPlans(t *testing.T) {
	withStructuredToken(t, mustMintAccessToken(t, "professional", false), func() {
		if AllowsStructuredLogging() {
			t.Fatal("non-compliance/governance license must not allow structured logging")
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

func TestLicenseTypePrefersLicClaim(t *testing.T) {
	claims := &token.TokenClaims{Lic: "compliance", Plan: "community"}
	if got := claims.LicenseType(); got != "compliance" {
		t.Fatalf("LicenseType() = %q, want compliance", got)
	}
}

func withStructuredToken(t *testing.T, raw string, fn func()) {
	t.Helper()
	resetStructuredCache()
	orig := accessTokenForStructuredLogging
	accessTokenForStructuredLogging = func() string { return raw }
	t.Cleanup(func() {
		accessTokenForStructuredLogging = orig
		resetStructuredCache()
	})
	fn()
}

func mustMintAccessToken(t *testing.T, licenseType string, tmp bool) string {
	t.Helper()
	now := time.Now()
	claims := &token.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Lic: licenseType,
		Tmp: tmp,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return raw
}

func resetStructuredCache() {
	structuredMu.Lock()
	defer structuredMu.Unlock()
	structuredCachedToken = ""
	structuredLoggingCached = false
}

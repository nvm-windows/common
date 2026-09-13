package license

import (
	"common/token"
	"testing"
	"time"
)

func TestEditionReportsLicensedEdition(t *testing.T) {
	for _, tt := range []struct {
		name string
		ents []string
		want string
	}{
		{name: "governance", ents: []string{"governance"}, want: "Governance"},
		{name: "compliance", ents: []string{"compliance"}, want: "Audit"},
		{name: "audit", ents: []string{"audit"}, want: "Audit"},
		{name: "build", ents: []string{"build"}, want: "Distro"},
		{name: "build+audit", ents: []string{"audit", "build"}, want: "Audit"},
		{name: "build+audit+governance", ents: []string{"build", "audit", "governance"}, want: "Governance"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			withEditionToken(t, mustMintAccessTokenEntitlements(t, false, tt.ents...))
			if got := Edition(); got != tt.want {
				t.Fatalf("Edition() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEditionFallsBackToCommunity(t *testing.T) {
	tmp, err := token.NewTemporaryToken(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"missing token":     "",
		"invalid token":     "not-a-jwt",
		"temporary token":   tmp,
		"empty entitlements": mustMintAccessTokenEntitlements(t, false),
		"expired token":     mustMintAccessTokenExpiringAt(t, "governance", time.Now().Add(-FeatureGracePeriod-time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			withEditionToken(t, raw)
			if got := Edition(); got != "Community" {
				t.Fatalf("Edition() = %q, want Community", got)
			}
		})
	}
}

func TestEditionDropsWhenLicenseVerifyStale(t *testing.T) {
	raw := mustMintAccessToken(t, "governance", false)
	withEditionToken(t, raw)
	if got := Edition(); got != "Governance" {
		t.Fatalf("Edition() = %q before stale", got)
	}

	origVerified := verifiedAtFn
	verifiedAtFn = func() string {
		return time.Now().Add(-(LicenseVerifyMaxAge + time.Hour)).UTC().Format(time.RFC3339)
	}
	t.Cleanup(func() { verifiedAtFn = origVerified })

	if got := Edition(); got != "Community" {
		t.Fatalf("Edition() = %q, want Community when verify stale", got)
	}
}

func withEditionToken(t *testing.T, raw string) {
	t.Helper()
	withCommercialTrustOK(t)
	orig := accessTokenForEdition
	accessTokenForEdition = func() string { return raw }
	t.Cleanup(func() { accessTokenForEdition = orig })
}

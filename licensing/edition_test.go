package license

import (
	"testing"
)

func TestEditionReportsLicensedEdition(t *testing.T) {
	for _, tt := range []struct {
		licenseType string
		want        string
	}{
		{licenseType: "governance", want: "Governance"},
		{licenseType: "compliance", want: "Compliance"},
		{licenseType: "COMMUNITY", want: "Community"},
	} {
		t.Run(tt.licenseType, func(t *testing.T) {
			withEditionToken(t, mustMintAccessToken(t, tt.licenseType, false))
			if got := Edition(); got != tt.want {
				t.Fatalf("Edition() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEditionFallsBackToCommunity(t *testing.T) {
	for name, raw := range map[string]string{
		"missing token":   "",
		"invalid token":   "not-a-jwt",
		"temporary token": mustMintAccessToken(t, "governance", true),
	} {
		t.Run(name, func(t *testing.T) {
			withEditionToken(t, raw)
			if got := Edition(); got != "Community" {
				t.Fatalf("Edition() = %q, want Community", got)
			}
		})
	}
}

func withEditionToken(t *testing.T, raw string) {
	t.Helper()
	orig := accessTokenForEdition
	accessTokenForEdition = func() string { return raw }
	t.Cleanup(func() { accessTokenForEdition = orig })
}

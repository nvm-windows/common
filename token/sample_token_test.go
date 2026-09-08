package token

import (
	"testing"
)

func TestSampleAccessTokenLicArray(t *testing.T) {
	// NewCo sample access token: lic is ["audit","build"] (unverified parse only).
	raw := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im52bS0yMDI2MDgifQ.eyJpc3MiOiJodHRwczovL2xpY2Vuc2luZy5hdXRob3IuaW8iLCJzdWIiOiJOZXdDbyAyIiwiYXVkIjoibnZtLXdpbmRvd3MiLCJleHAiOjE4MTQzMTE5MjksImlhdCI6MTc4ODgzMzQ4MSwib3JnIjoiMDFLVllKMEpORVJXRFdLN1JNMzlLQk1RTkQiLCJsaWMiOlsiYXVkaXQiLCJidWlsZCJdLCJqdGkiOiIxNzg4NzU3MjAwLWw2ZzFtaSJ9.sv7IAJCVss_K3IfSilPu2d6Klv3wrcL7tezHanwxdC4wSxiZoQ5l29AFp6dK4sZlKJzpNj1fIVtXGsCek89MEQ"
	parsed, err := ParseUnverified(raw)
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(*TokenClaims)
	if !claims.HasEntitlement(EntitlementAudit) || !claims.HasEntitlement(EntitlementBuild) {
		t.Fatalf("ents=%v", claims.Entitlements())
	}
	if claims.PrimaryEntitlement() != EntitlementAudit {
		t.Fatalf("primary=%q", claims.PrimaryEntitlement())
	}
	if claims.HasEntitlement(EntitlementGovernance) {
		t.Fatal("unexpected governance")
	}
}

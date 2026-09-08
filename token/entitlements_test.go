package token

import (
	"encoding/json"
	"testing"
)

func TestLicenseEntitlementsUnmarshalStringAndArray(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var claims TokenClaims
		if err := json.Unmarshal([]byte(`{"lic":"governance","plan":"community"}`), &claims); err != nil {
			t.Fatal(err)
		}
		if got := claims.PrimaryEntitlement(); got != EntitlementGovernance {
			t.Fatalf("PrimaryEntitlement() = %q", got)
		}
		if !claims.HasEntitlement(EntitlementGovernance) {
			t.Fatal("expected governance")
		}
	})
	t.Run("array", func(t *testing.T) {
		var claims TokenClaims
		if err := json.Unmarshal([]byte(`{"lic":["audit","build"]}`), &claims); err != nil {
			t.Fatal(err)
		}
		if got := claims.PrimaryEntitlement(); got != EntitlementAudit {
			t.Fatalf("PrimaryEntitlement() = %q, want audit", got)
		}
		if !claims.HasEntitlement(EntitlementBuild) {
			t.Fatal("expected build")
		}
	})
	t.Run("plan fallback", func(t *testing.T) {
		var claims TokenClaims
		if err := json.Unmarshal([]byte(`{"plan":"governance"}`), &claims); err != nil {
			t.Fatal(err)
		}
		if got := claims.LicenseType(); got != EntitlementGovernance {
			t.Fatalf("LicenseType() = %q", got)
		}
	})
}

func TestHasEntitlementComplianceAlias(t *testing.T) {
	claims := &TokenClaims{Lic: LicenseEntitlements{EntitlementCompliance}}
	if !claims.HasEntitlement(EntitlementAudit) {
		t.Fatal("compliance should satisfy audit entitlement")
	}
}

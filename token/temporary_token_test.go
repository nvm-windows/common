package token

import (
	"testing"
	"time"
)

func TestNewTemporaryTokenHasEmptyLic(t *testing.T) {
	raw, err := NewTemporaryToken(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseUnverified(raw)
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(*TokenClaims)
	if !claims.Tmp {
		t.Fatal("expected tmp=true")
	}
	if len(claims.Lic) != 0 {
		t.Fatalf("Lic = %#v, want empty array", claims.Lic)
	}
	if claims.Plan != "" {
		t.Fatalf("Plan = %q, want empty", claims.Plan)
	}
	if ents := claims.Entitlements(); len(ents) != 0 {
		t.Fatalf("Entitlements() = %#v, want empty", ents)
	}
	if claims.HasEntitlement(EntitlementCommunity) {
		t.Fatal("temporary token must not claim community entitlement")
	}
}

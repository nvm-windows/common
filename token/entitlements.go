package token

import (
	"encoding/json"
	"strings"
)

// Known license entitlements in access-token lic claims.
const (
	EntitlementBuild       = "build"
	EntitlementAudit       = "audit"
	EntitlementGovernance  = "governance"
	EntitlementCompliance  = "compliance" // legacy Audit alias
	EntitlementCommunity   = "community"
)

// LicenseEntitlements unmarshals JWT lic as either a string or string array.
// New tokens use ["build","audit","governance"]; older tokens used a single string.
type LicenseEntitlements []string

func (e LicenseEntitlements) MarshalJSON() ([]byte, error) {
	if e == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(e))
}

func (e *LicenseEntitlements) UnmarshalJSON(data []byte) error {
	if e == nil {
		return nil
	}
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 || string(data) == "null" {
		*e = nil
		return nil
	}
	if data[0] == '"' {
		var one string
		if err := json.Unmarshal(data, &one); err != nil {
			return err
		}
		one = strings.TrimSpace(one)
		if one == "" {
			*e = nil
			return nil
		}
		*e = LicenseEntitlements{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	out := make(LicenseEntitlements, 0, len(many))
	for _, item := range many {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	*e = out
	return nil
}


// Entitlements returns normalized lic values, falling back to plan when lic is empty.
func (c *TokenClaims) Entitlements() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Lic)+1)
	seen := map[string]struct{}{}
	add := func(raw string) {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, item := range c.Lic {
		add(item)
	}
	if len(out) == 0 {
		add(c.Plan)
	}
	return out
}

// HasEntitlement reports whether lic/plan grants the named entitlement.
// Legacy aliases: compliance ≡ audit.
func (c *TokenClaims) HasEntitlement(name string) bool {
	want := strings.ToLower(strings.TrimSpace(name))
	if want == "" {
		return false
	}
	for _, got := range c.Entitlements() {
		if entitlementMatches(got, want) {
			return true
		}
	}
	return false
}

func entitlementMatches(got, want string) bool {
	if got == want {
		return true
	}
	// compliance was the historical Audit JWT value.
	if want == EntitlementAudit && got == EntitlementCompliance {
		return true
	}
	if want == EntitlementCompliance && got == EntitlementAudit {
		return true
	}
	return false
}

// PrimaryEntitlement returns the highest product entitlement for labels:
// governance > audit/compliance > build > first non-community value > "".
func (c *TokenClaims) PrimaryEntitlement() string {
	ents := c.Entitlements()
	if len(ents) == 0 {
		return ""
	}
	rank := func(v string) int {
		switch v {
		case EntitlementGovernance:
			return 4
		case EntitlementAudit, EntitlementCompliance:
			return 3
		case EntitlementBuild:
			return 2
		case EntitlementCommunity:
			return 0
		default:
			return 1
		}
	}
	best := ""
	bestRank := -1
	for _, e := range ents {
		r := rank(e)
		if r > bestRank {
			best = e
			bestRank = r
		}
	}
	return best
}

// LicenseType returns the primary commercial entitlement from lic (or plan fallback).
// Prefer PrimaryEntitlement for new code; kept for existing call sites.
func (c *TokenClaims) LicenseType() string {
	return c.PrimaryEntitlement()
}

// IsCommercialEntitlement reports whether v is a paid product entitlement.
func IsCommercialEntitlement(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case EntitlementBuild, EntitlementAudit, EntitlementGovernance, EntitlementCompliance:
		return true
	case EntitlementCommunity, "":
		return false
	default:
		// Legacy unknown plan strings were treated as commercial for banners/notices.
		return true
	}
}

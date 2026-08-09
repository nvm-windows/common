package license

import (
	"common/token"
	"testing"
)

func TestAccessTokenVerificationLabel(t *testing.T) {
	old := token.LastVerifySource
	t.Cleanup(func() { token.LastVerifySource = old })

	cases := []struct {
		src  token.VerifySource
		want string
	}{
		{token.VerifySourceLive, "verified (live JWKS)"},
		{token.VerifySourceOffline, "verified (offline JWKS)"},
		{token.VerifySourceNone, "verified"},
	}
	for _, tt := range cases {
		token.LastVerifySource = tt.src
		if got := accessTokenVerificationLabel(); got != tt.want {
			t.Fatalf("src=%q got %q want %q", tt.src, got, tt.want)
		}
	}
}

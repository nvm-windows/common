package token

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveJKUUsesHeaderThenClaimThenDefault(t *testing.T) {
	got, err := resolveJKU(map[string]interface{}{"jku": "https://licensing.author.io/.well-known/jwks"}, nil)
	if err != nil || got != defaultJWKSURL {
		t.Fatalf("header jku = %q err=%v", got, err)
	}

	got, err = resolveJKU(nil, &TokenClaims{JKU: "https://licensing.author.io/.well-known/jwks"})
	if err != nil || got != defaultJWKSURL {
		t.Fatalf("claim jku = %q err=%v", got, err)
	}

	got, err = resolveJKU(nil, &TokenClaims{})
	if err != nil || got != defaultJWKSURL {
		t.Fatalf("default jku = %q err=%v", got, err)
	}

	got, err = resolveJKU(map[string]interface{}{"jku": "https://licensing.author.io"}, nil)
	if err != nil || got != defaultJWKSURL {
		t.Fatalf("origin-only jku = %q err=%v", got, err)
	}

	if _, err := resolveJKU(map[string]interface{}{"jku": "https://evil.example/jwks"}, nil); err == nil {
		t.Fatal("expected invalid jku error")
	}
}

func TestFetchJWKSSendsBearerAccessToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kid":"other","kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`))
	}))
	t.Cleanup(srv.Close)

	_, err := fetchPublicKeyFromJKUSync(srv.URL, "kid-1", "header.payload.sig")
	if err == nil || err.Error() != `no jwk found for kid "kid-1"` {
		t.Fatalf("err = %v", err)
	}
	if gotAuth != "Bearer header.payload.sig" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}

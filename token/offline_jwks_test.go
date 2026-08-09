package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestFetchPublicKeyAirGappedSkipsHTTP(t *testing.T) {
	restoreOfflineHooks(t)

	priv := mustECDSA(t)
	kid := "nvm-test-1"
	jwksJSON := mustJWKSJSON(t, kid, &priv.PublicKey)

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		t.Error("live JWKS must not be fetched when airgapped")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	AirGappedFn = func() bool { return true }
	LoadJwksCoseFn = func() []byte { return []byte("blob") }
	verifyJwksCoseBlob = func(blob []byte) ([]byte, error) {
		if string(blob) != "blob" {
			t.Fatalf("blob = %q", blob)
		}
		return jwksJSON, nil
	}

	key, err := fetchPublicKeyForJWT(srv.URL, kid, "tok")
	if err != nil {
		t.Fatalf("fetchPublicKeyForJWT() error = %v", err)
	}
	if key == nil || key.X.Cmp(priv.PublicKey.X) != 0 {
		t.Fatal("offline key mismatch")
	}
	if LastVerifySource != VerifySourceOffline {
		t.Fatalf("LastVerifySource = %q, want offline", LastVerifySource)
	}
	if hits != 0 {
		t.Fatalf("live hits = %d, want 0", hits)
	}
}

func TestFetchPublicKeyLiveSuccessNeverLoadsBlob(t *testing.T) {
	restoreOfflineHooks(t)

	priv := mustECDSA(t)
	kid := "nvm-live-1"
	jwksJSON := mustJWKSJSON(t, kid, &priv.PublicKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	t.Cleanup(srv.Close)

	AirGappedFn = func() bool { return false }
	LoadJwksCoseFn = func() []byte {
		t.Fatal("offline blob must not load on live JWKS success")
		return nil
	}

	key, err := fetchPublicKeyForJWT(srv.URL, kid, "tok")
	if err != nil {
		t.Fatalf("fetchPublicKeyForJWT() error = %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if LastVerifySource != VerifySourceLive {
		t.Fatalf("LastVerifySource = %q, want live", LastVerifySource)
	}
}

func TestFetchPublicKeyLiveUnknownKidDoesNotFallback(t *testing.T) {
	restoreOfflineHooks(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kid":"other","kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`))
	}))
	t.Cleanup(srv.Close)

	blobLoaded := false
	AirGappedFn = func() bool { return false }
	LoadJwksCoseFn = func() []byte {
		blobLoaded = true
		return []byte("blob")
	}

	_, err := fetchPublicKeyForJWT(srv.URL, "nvm-missing", "tok")
	if err == nil || !strings.Contains(err.Error(), `no jwk found for kid "nvm-missing"`) {
		t.Fatalf("err = %v", err)
	}
	if blobLoaded {
		t.Fatal("offline blob loaded after live unknown kid")
	}
}

func TestFetchPublicKeyLiveUnavailableFallsBackOffline(t *testing.T) {
	restoreOfflineHooks(t)

	priv := mustECDSA(t)
	kid := "nvm-off-1"
	jwksJSON := mustJWKSJSON(t, kid, &priv.PublicKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	AirGappedFn = func() bool { return false }
	LoadJwksCoseFn = func() []byte { return []byte("blob") }
	verifyJwksCoseBlob = func(blob []byte) ([]byte, error) { return jwksJSON, nil }

	key, err := fetchPublicKeyForJWT(srv.URL, kid, "tok")
	if err != nil {
		t.Fatalf("fetchPublicKeyForJWT() error = %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if LastVerifySource != VerifySourceOffline {
		t.Fatalf("LastVerifySource = %q, want offline", LastVerifySource)
	}
}

func TestFetchPublicKeyOfflineRejectsBadKidPrefix(t *testing.T) {
	restoreOfflineHooks(t)

	AirGappedFn = func() bool { return true }
	LoadJwksCoseFn = func() []byte { return []byte("blob") }
	verifyJwksCoseBlob = func(blob []byte) ([]byte, error) {
		t.Fatal("verify must not run for non-nvm kid")
		return nil, nil
	}

	_, err := fetchPublicKeyForJWT("https://example.invalid/jwks", "other-kid", "tok")
	if err == nil || !errors.Is(err, errJWKSUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchPublicKeyOfflineSidecar(t *testing.T) {
	restoreOfflineHooks(t)

	priv := mustECDSA(t)
	kid := "nvm-side-1"
	jwksJSON := mustJWKSJSON(t, kid, &priv.PublicKey)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, jwksCoseSidecarName), []byte("sidecar"), 0o600); err != nil {
		t.Fatal(err)
	}

	AirGappedFn = func() bool { return true }
	LoadJwksCoseFn = func() []byte { return nil }
	ExecutableDirFn = func() string { return dir }
	verifyJwksCoseBlob = func(blob []byte) ([]byte, error) {
		if string(blob) != "sidecar" {
			t.Fatalf("blob = %q", blob)
		}
		return jwksJSON, nil
	}

	key, err := fetchPublicKeyForJWT("https://example.invalid/jwks", kid, "tok")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestFetchPublicKeyOfflineVerifyFailure(t *testing.T) {
	restoreOfflineHooks(t)

	AirGappedFn = func() bool { return true }
	LoadJwksCoseFn = func() []byte { return []byte("blob") }
	verifyJwksCoseBlob = func(blob []byte) ([]byte, error) {
		return nil, errors.New("bad O=")
	}

	_, err := fetchPublicKeyForJWT("https://example.invalid/jwks", "nvm-x", "tok")
	if err == nil || !strings.Contains(err.Error(), "bad O=") {
		t.Fatalf("err = %v", err)
	}
}

func TestSetOfflineJWKSVerifiesJWT(t *testing.T) {
	restoreOfflineHooks(t)

	priv := mustECDSA(t)
	kid := "nvm-set-1"
	raw := mustMintAccessJWT(t, kid, priv)
	jwksJSON := mustJWKSJSON(t, kid, &priv.PublicKey)

	oldFail := FailOpenOnJWKSUnavailable
	FailOpenOnJWKSUnavailable = false
	t.Cleanup(func() { FailOpenOnJWKSUnavailable = oldFail })

	AirGappedFn = func() bool { return true }
	LoadJwksCoseFn = func() []byte { return []byte("blob") }
	verifyJwksCoseBlob = func(blob []byte) ([]byte, error) { return jwksJSON, nil }

	if err := Set(raw); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if LastVerifySource != VerifySourceOffline {
		t.Fatalf("LastVerifySource = %q", LastVerifySource)
	}
	if Access == nil {
		t.Fatal("Access is nil")
	}
}

func restoreOfflineHooks(t *testing.T) {
	t.Helper()
	oldAir := AirGappedFn
	oldLoad := LoadJwksCoseFn
	oldExe := ExecutableDirFn
	oldVerify := verifyJwksCoseBlob
	oldSrc := LastVerifySource
	t.Cleanup(func() {
		AirGappedFn = oldAir
		LoadJwksCoseFn = oldLoad
		ExecutableDirFn = oldExe
		verifyJwksCoseBlob = oldVerify
		LastVerifySource = oldSrc
	})
}

func mustECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func mustJWKSJSON(t *testing.T, kid string, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	body, err := json.Marshal(jwksEnvelope{Keys: []jwk{{
		Kid: kid,
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
		Alg: "ES256",
		Use: "sig",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func mustMintAccessJWT(t *testing.T, kid string, priv *ecdsa.PrivateKey) string {
	t.Helper()
	now := time.Now()
	claims := &TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Plan:  "governance",
		Lic:   "governance",
		JKU:   defaultJWKSURL,
		Roles: []string{"admin"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	tok.Header["jku"] = defaultJWKSURL
	raw, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

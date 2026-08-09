package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	gohttp "net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var Access *AccessToken

type TokenClaims struct {
	jwt.RegisteredClaims
	Plan  string   `json:"plan"`
	Lic   string   `json:"lic"`
	Org   string   `json:"org"`
	JKU   string   `json:"jku,omitempty"`
	Roles []string `json:"roles"`
	Tmp   bool     `json:"tmp"`
}

const (
	defaultJWKSURL   = "https://licensing.author.io/.well-known/jwks"
	allowedJKUOrigin = "https://licensing.author.io"
)

// LicenseType returns the commercial license type from lic, falling back to plan.
func (c *TokenClaims) LicenseType() string {
	if c == nil {
		return ""
	}
	if lic := strings.TrimSpace(c.Lic); lic != "" {
		return lic
	}
	return strings.TrimSpace(c.Plan)
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type jwksEnvelope struct {
	Keys []jwk `json:"keys"`
}

var errJWKSUnavailable = errors.New("jwks unavailable")

// FailOpenOnJWKSUnavailable controls whether Set accepts an unverified token when
// JWKS discovery is unreachable. OSS builds keep this true; certified enhanced
// preferences init sets it false.
var FailOpenOnJWKSUnavailable = true

// AllowTemporaryTokenFallback controls whether licensing may mint an unsigned
// temporary community token after verification or fetch failures.
var AllowTemporaryTokenFallback = true

const jwksFetchTimeout = 1000 * time.Millisecond

var jwksHTTPClient = &gohttp.Client{
	Transport: &gohttp.Transport{
		Proxy:                 gohttp.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: jwksFetchTimeout}).DialContext,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   jwksFetchTimeout,
		ResponseHeaderTimeout: jwksFetchTimeout,
		ExpectContinueTimeout: 50 * time.Millisecond,
	},
	Timeout: jwksFetchTimeout,
}

func Set(raw string) error {
	LastVerifySource = VerifySourceNone

	unverified, _, err := jwt.NewParser().ParseUnverified(raw, &TokenClaims{})
	if err != nil {
		return err
	}

	claims, ok := unverified.Claims.(*TokenClaims)
	if !ok {
		return fmt.Errorf("invalid token claims type")
	}

	if claims.Tmp {
		Access = &AccessToken{Token: unverified}
		return nil
	}

	jku, err := resolveJKU(unverified.Header, claims)
	if err != nil {
		return err
	}

	kid, ok := unverified.Header["kid"].(string)
	if !ok || kid == "" {
		return fmt.Errorf("token header missing kid")
	}

	publicKey, err := fetchPublicKeyForJWT(jku, kid, raw)
	if err != nil {
		if FailOpenOnJWKSUnavailable && errors.Is(err, errJWKSUnavailable) {
			Access = &AccessToken{Token: unverified}
			return nil
		}

		return err
	}

	verifiedClaims := &TokenClaims{}
	verified, err := jwt.ParseWithClaims(raw, verifiedClaims, func(parsed *jwt.Token) (interface{}, error) {
		if _, ok := parsed.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", parsed.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return err
	}

	Access = &AccessToken{Token: verified}

	return nil
}

// ParseUnverified parses a JWT access token without signature verification.
func ParseUnverified(raw string) (*AccessToken, error) {
	unverified, _, err := jwt.NewParser().ParseUnverified(raw, &TokenClaims{})
	if err != nil {
		return nil, err
	}

	return &AccessToken{Token: unverified}, nil
}

// IsJWKSUnavailable reports whether err is a JWKS fetch/connectivity failure.
func IsJWKSUnavailable(err error) bool {
	return errors.Is(err, errJWKSUnavailable)
}

func NewTemporaryToken(ttl time.Duration) (string, error) {
	now := time.Now()
	claims := &TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Plan:  "community",
		Roles: []string{"community"},
		Tmp:   true,
	}

	tmp := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	token, err := tmp.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return "", err
	}

	return token, nil
}

func resolveJKU(header map[string]interface{}, claims *TokenClaims) (string, error) {
	jku := ""
	if header != nil {
		if v, ok := header["jku"].(string); ok {
			jku = strings.TrimSpace(v)
		}
	}
	if jku == "" && claims != nil {
		jku = strings.TrimSpace(claims.JKU)
	}
	if jku == "" || strings.TrimRight(jku, "/") == allowedJKUOrigin {
		jku = defaultJWKSURL
	}
	if !strings.HasPrefix(jku, allowedJKUOrigin+"/") {
		return "", fmt.Errorf("invalid jku URL: %s", jku)
	}
	return jku, nil
}

func fetchPublicKeyFromJKU(jkuURL, kid, accessToken string) (*ecdsa.PublicKey, error) {
	type jwksResult struct {
		key *ecdsa.PublicKey
		err error
	}

	result := make(chan jwksResult, 1)

	go func() {
		key, err := fetchPublicKeyFromJKUSync(jkuURL, kid, accessToken)
		result <- jwksResult{key: key, err: err}
	}()

	select {
	case res := <-result:
		return res.key, res.err
	case <-time.After(jwksFetchTimeout):
		return nil, fmt.Errorf("%w: timed out after %s", errJWKSUnavailable, jwksFetchTimeout)
	}
}

func fetchPublicKeyFromJKUSync(jkuURL, kid, accessToken string) (*ecdsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), jwksFetchTimeout)
	defer cancel()

	req, err := gohttp.NewRequestWithContext(ctx, gohttp.MethodGet, jkuURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwks request: %w", err)
	}
	if accessToken = strings.TrimSpace(accessToken); accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := jwksHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to download jwks: %v", errJWKSUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 || resp.StatusCode == 429 {
		return nil, fmt.Errorf("%w: failed to download jwks: status %d", errJWKSUnavailable, resp.StatusCode)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to download jwks: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read jwks response: %w", err)
	}

	keys, err := parseJWKSKeys(body)
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		if key.Kid != kid {
			continue
		}

		publicKey, err := jwkToECDSAPublicKey(key)
		if err != nil {
			return nil, err
		}

		return publicKey, nil
	}

	return nil, fmt.Errorf("no jwk found for kid %q", kid)
}

func parseJWKSKeys(body []byte) ([]jwk, error) {
	var envelope jwksEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Keys) > 0 {
		return envelope.Keys, nil
	}

	keys := []jwk{}
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, fmt.Errorf("failed to parse jwks: %w", err)
	}
	return keys, nil
}

func jwkToECDSAPublicKey(key jwk) (*ecdsa.PublicKey, error) {
	if key.Kty != "EC" {
		return nil, fmt.Errorf("unsupported jwk kty %q", key.Kty)
	}

	if key.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported jwk crv %q", key.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("invalid jwk x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid jwk y coordinate: %w", err)
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("jwk public key is not on curve")
	}

	return pub, nil
}

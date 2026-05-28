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
	Roles []string `json:"roles"`
	Tmp   bool     `json:"tmp"`
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

const jwksFetchTimeout = 300 * time.Millisecond

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

	jku, ok := unverified.Header["jku"].(string)
	if !ok || jku == "" {
		return fmt.Errorf("token header missing jku")
	}

	if !strings.HasPrefix(jku, "https://licensing.author.io/") {
		return fmt.Errorf("invalid jku URL: %s", jku)
	}

	kid, ok := unverified.Header["kid"].(string)
	if !ok || kid == "" {
		return fmt.Errorf("token header missing kid")
	}

	publicKey, err := fetchPublicKeyFromJKU(jku, kid)
	if err != nil {
		if errors.Is(err, errJWKSUnavailable) {
			// If key discovery is unreachable/offline, fail open to keep startup responsive.
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

func fetchPublicKeyFromJKU(jkuURL, kid string) (*ecdsa.PublicKey, error) {
	type jwksResult struct {
		key *ecdsa.PublicKey
		err error
	}

	result := make(chan jwksResult, 1)

	go func() {
		key, err := fetchPublicKeyFromJKUSync(jkuURL, kid)
		result <- jwksResult{key: key, err: err}
	}()

	select {
	case res := <-result:
		return res.key, res.err
	case <-time.After(jwksFetchTimeout):
		return nil, fmt.Errorf("%w: timed out after %s", errJWKSUnavailable, jwksFetchTimeout)
	}
}

func fetchPublicKeyFromJKUSync(jkuURL, kid string) (*ecdsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), jwksFetchTimeout)
	defer cancel()

	req, err := gohttp.NewRequestWithContext(ctx, gohttp.MethodGet, jkuURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwks request: %w", err)
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

	keys := []jwk{}

	var envelope jwksEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Keys) > 0 {
		keys = envelope.Keys
	} else {
		if err := json.Unmarshal(body, &keys); err != nil {
			return nil, fmt.Errorf("failed to parse jwks: %w", err)
		}
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

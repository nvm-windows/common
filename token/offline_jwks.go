package token

import (
	commoncose "common/cose"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// AuthorJWKSOrg is the only organization allowed to sign offline JWKS COSE blobs.
	AuthorJWKSOrg       = "Author Software Inc."
	jwksKidPrefix       = "nvm-"
	jwksCoseSidecarName = "nvm-jwks.cose"
)

// VerifySource records how the last successful token.Set signature check resolved.
type VerifySource string

const (
	VerifySourceNone    VerifySource = ""
	VerifySourceLive    VerifySource = "live"
	VerifySourceOffline VerifySource = "offline"
)

// LastVerifySource is set by Set after a successful signature check.
var LastVerifySource VerifySource

// AirGappedFn, when true, skips live JWKS entirely.
var AirGappedFn = func() bool { return false }

// LoadJwksCoseFn returns HKLM policy then prefs REG_BINARY (wired by licensing).
var LoadJwksCoseFn = func() []byte { return nil }

// ExecutableDirFn is the directory that may contain nvm-jwks.cose.
var ExecutableDirFn = defaultExecutableDir

var verifyJwksCoseBlob = func(blob []byte) ([]byte, error) {
	return commoncose.VerifySign1(blob, []string{AuthorJWKSOrg})
}

func defaultExecutableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

func fetchPublicKeyForJWT(jkuURL, kid, accessToken string) (*ecdsa.PublicKey, error) {
	airgapped := AirGappedFn != nil && AirGappedFn()
	if airgapped {
		key, err := fetchPublicKeyFromOfflineJWKS(kid)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errJWKSUnavailable, err)
		}
		LastVerifySource = VerifySourceOffline
		return key, nil
	}

	key, err := fetchPublicKeyFromJKU(jkuURL, kid, accessToken)
	if err == nil {
		LastVerifySource = VerifySourceLive
		return key, nil
	}
	if !errors.Is(err, errJWKSUnavailable) {
		return nil, err
	}

	offlineKey, offlineErr := fetchPublicKeyFromOfflineJWKS(kid)
	if offlineErr == nil {
		LastVerifySource = VerifySourceOffline
		return offlineKey, nil
	}

	return nil, fmt.Errorf("%w (offline JWKS: %v)", err, offlineErr)
}

func fetchPublicKeyFromOfflineJWKS(kid string) (*ecdsa.PublicKey, error) {
	if !strings.HasPrefix(kid, jwksKidPrefix) {
		return nil, fmt.Errorf("offline JWKS rejects kid %q (want prefix %s)", kid, jwksKidPrefix)
	}

	blob := loadJwksCoseBlob()
	if len(blob) == 0 {
		return nil, fmt.Errorf("offline JWKS COSE blob not found")
	}

	payload, err := verifyJwksCoseBlob(blob)
	if err != nil {
		return nil, fmt.Errorf("offline JWKS COSE verify failed: %w", err)
	}

	keys, err := parseJWKSKeys(payload)
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		if key.Kid != kid || !strings.HasPrefix(key.Kid, jwksKidPrefix) {
			continue
		}
		return jwkToECDSAPublicKey(key)
	}

	return nil, fmt.Errorf("no jwk found for kid %q in offline JWKS", kid)
}

func loadJwksCoseBlob() []byte {
	if LoadJwksCoseFn != nil {
		if blob := LoadJwksCoseFn(); len(blob) > 0 {
			return blob
		}
	}

	dir := ""
	if ExecutableDirFn != nil {
		dir = strings.TrimSpace(ExecutableDirFn())
	}
	if dir == "" {
		return nil
	}

	data, err := os.ReadFile(filepath.Join(dir, jwksCoseSidecarName))
	if err != nil || len(data) == 0 {
		return nil
	}
	return data
}

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	coseecdsa "github.com/ldclabs/cose/key/ecdsa"
)

// ExternalAAD is the COSE Sign1 external AAD. CoseSignTool defaults to empty
// unless --ExternalData is set.
var ExternalAAD []byte

var (
	chainRootsMu     sync.RWMutex
	chainVerifyRoots *x509.CertPool
)

// SetChainVerifyRoots overrides x509.SystemCertPool for tests. Pass nil to restore.
func SetChainVerifyRoots(roots *x509.CertPool) {
	chainRootsMu.Lock()
	defer chainRootsMu.Unlock()
	chainVerifyRoots = roots
}

// VerifySign1 validates a COSE Sign1 envelope (x5chain → Windows roots →
// ExtKeyUsageCodeSigning → signer O= in allowedOrgs) and returns the payload.
// Chain validity is checked at signing time (COSE iat, else leaf NotAfter),
// not wall-clock now — Azure Trusted Signing leaves rotate about every 24h.
func VerifySign1(data []byte, allowedOrgs []string) ([]byte, error) {
	msg := &cose.Sign1Message[[]byte]{}
	if err := msg.UnmarshalCBOR(data); err != nil {
		return nil, fmt.Errorf("invalid COSE Sign1 envelope: %w", err)
	}

	chain, err := x509ChainFromHeaders(msg.Protected, msg.Unprotected)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("COSE Sign1 missing x5chain certificate")
	}

	if err := verifyX509Chain(chain, msg.Protected, msg.Unprotected); err != nil {
		return nil, err
	}

	signerOrg := certificateOrganization(chain[0])
	if signerOrg == "" {
		return nil, fmt.Errorf("unable to resolve signer organization from certificate")
	}
	if !isAllowedSigner(signerOrg, allowedOrgs) {
		return nil, fmt.Errorf(
			"signer %q is not allowed (allowed signers: %s)",
			signerOrg,
			strings.Join(allowedOrgs, ", "),
		)
	}

	alg, err := msg.Protected.GetInt(iana.HeaderParameterAlg)
	if err != nil {
		return nil, fmt.Errorf("COSE Sign1 missing algorithm: %w", err)
	}

	verifier, err := verifierFromCertificate(chain[0], alg)
	if err != nil {
		return nil, err
	}
	if err := msg.Verify(verifier, ExternalAAD); err != nil {
		return nil, fmt.Errorf("COSE Sign1 signature invalid: %w", err)
	}

	if len(msg.Payload) == 0 {
		return nil, fmt.Errorf("COSE Sign1 payload is empty")
	}

	return msg.Payload, nil
}

func x509ChainFromHeaders(protected, unprotected cose.Headers) ([]*x509.Certificate, error) {
	for _, headers := range []cose.Headers{unprotected, protected} {
		if headers == nil {
			continue
		}
		for _, param := range []any{iana.HeaderParameterX5Chain, iana.HeaderParameterX5Bag} {
			if !headers.Has(param) {
				continue
			}
			certs, err := certificatesFromHeaderValue(headers.Get(param))
			if err != nil {
				return nil, err
			}
			if len(certs) > 0 {
				return certs, nil
			}
		}
	}
	return nil, nil
}

func certificatesFromHeaderValue(value any) ([]*x509.Certificate, error) {
	switch v := value.(type) {
	case []byte:
		cert, err := x509.ParseCertificate(v)
		if err != nil {
			return nil, fmt.Errorf("parse x5chain certificate: %w", err)
		}
		return []*x509.Certificate{cert}, nil
	case []any:
		certs := make([]*x509.Certificate, 0, len(v))
		for i, item := range v {
			raw, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("x5chain entry %d is not a byte string", i)
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return nil, fmt.Errorf("parse x5chain certificate %d: %w", i, err)
			}
			certs = append(certs, cert)
		}
		return certs, nil
	default:
		return nil, fmt.Errorf("unsupported x5chain header type %T", value)
	}
}

func verifyX509Chain(chain []*x509.Certificate, protected, unprotected cose.Headers) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	chainRootsMu.RLock()
	override := chainVerifyRoots
	chainRootsMu.RUnlock()
	if override != nil {
		roots = override
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediates.AddCert(chain[i])
	}

	at := chainVerifyTime(chain[0], protected, unprotected)
	_, err = chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// headerParameterIat is RFC 9052 "iat" (issued-at), Unix seconds.
const headerParameterIat = 6

// chainVerifyTime is the instant used for x509 path building.
//
// Azure Trusted Signing / Artifact Signing issues ~24h leaf certs. Verifying
// "now" makes every worker fail the day after publish. Authenticode solves this
// with an RFC3161 timestamp; COSE Sign1 here only has x5chain (+ optional iat).
// We verify the chain as of signing time: COSE iat when present and inside the
// leaf window, otherwise the last second the leaf was valid if it has already
// expired. The signature still has to match the embedded public key.
func chainVerifyTime(leaf *x509.Certificate, protected, unprotected cose.Headers) time.Time {
	now := time.Now()
	if leaf == nil {
		return now
	}

	if iat, ok := coseIssuedAt(protected, unprotected); ok {
		skew := 5 * time.Minute
		if !iat.Before(leaf.NotBefore.Add(-skew)) && !iat.After(leaf.NotAfter.Add(skew)) {
			return iat
		}
	}

	if now.After(leaf.NotAfter) {
		return leaf.NotAfter.Add(-time.Second)
	}
	if now.Before(leaf.NotBefore) {
		return leaf.NotBefore
	}
	return now
}

func coseIssuedAt(headers ...cose.Headers) (time.Time, bool) {
	for _, h := range headers {
		if h == nil || !h.Has(headerParameterIat) {
			continue
		}
		if n, err := h.GetInt(headerParameterIat); err == nil {
			if n > 0 {
				return time.Unix(int64(n), 0).UTC(), true
			}
		}
		switch v := h.Get(headerParameterIat).(type) {
		case int64:
			if v > 0 {
				return time.Unix(v, 0).UTC(), true
			}
		case uint64:
			if v > 0 {
				return time.Unix(int64(v), 0).UTC(), true
			}
		case int:
			if v > 0 {
				return time.Unix(int64(v), 0).UTC(), true
			}
		}
	}
	return time.Time{}, false
}

func certificateOrganization(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if len(cert.Subject.Organization) > 0 {
		return strings.TrimSpace(cert.Subject.Organization[0])
	}
	return strings.TrimSpace(cert.Subject.CommonName)
}

func verifierFromCertificate(cert *x509.Certificate, alg int) (key.Verifier, error) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return newRSAVerifier(pub, alg)
	case *ecdsa.PublicKey:
		coseKey, err := coseecdsa.KeyFromPublic(pub)
		if err != nil {
			return nil, err
		}
		if err := coseKey.Set(iana.KeyParameterAlg, alg); err != nil {
			return nil, err
		}
		return coseecdsa.NewVerifier(coseKey)
	default:
		return nil, fmt.Errorf("unsupported signing key type %T", cert.PublicKey)
	}
}

type rsaVerifier struct {
	alg key.Alg
	pub *rsa.PublicKey
}

func newRSAVerifier(pub *rsa.PublicKey, alg int) (key.Verifier, error) {
	switch alg {
	case iana.AlgorithmRS256, iana.AlgorithmRS384, iana.AlgorithmRS512, iana.AlgorithmPS256, iana.AlgorithmPS384, iana.AlgorithmPS512:
	default:
		return nil, fmt.Errorf("unsupported RSA COSE algorithm %d", alg)
	}
	return &rsaVerifier{alg: key.Alg(alg), pub: pub}, nil
}

func (v *rsaVerifier) Verify(data, signature []byte) error {
	hash, err := rsaHash(v.alg)
	if err != nil {
		return err
	}
	digest, err := hashPayload(hash, data)
	if err != nil {
		return err
	}

	switch int(v.alg) {
	case iana.AlgorithmRS256, iana.AlgorithmRS384, iana.AlgorithmRS512:
		if err := rsa.VerifyPKCS1v15(v.pub, hash, digest, signature); err != nil {
			return fmt.Errorf("invalid RSA PKCS1v1.5 signature: %w", err)
		}
		return nil
	case iana.AlgorithmPS256, iana.AlgorithmPS384, iana.AlgorithmPS512:
		if err := rsa.VerifyPSS(v.pub, hash, digest, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}); err != nil {
			return fmt.Errorf("invalid RSA-PSS signature: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported RSA COSE algorithm %d", v.alg)
	}
}

func (v *rsaVerifier) Key() key.Key {
	return key.Key{
		iana.KeyParameterKty: iana.KeyTypeRSA,
		iana.KeyParameterAlg: int(v.alg),
	}
}

func rsaHash(alg key.Alg) (crypto.Hash, error) {
	switch int(alg) {
	case iana.AlgorithmRS256, iana.AlgorithmPS256:
		return crypto.SHA256, nil
	case iana.AlgorithmRS384, iana.AlgorithmPS384:
		return crypto.SHA384, nil
	case iana.AlgorithmRS512, iana.AlgorithmPS512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported RSA COSE algorithm %d", alg)
	}
}

func hashPayload(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("hash function unavailable")
	}
	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func isAllowedSigner(signer string, allowed []string) bool {
	candidate := strings.TrimSpace(signer)
	if candidate == "" {
		return false
	}
	for _, allowedSigner := range allowed {
		if strings.EqualFold(candidate, strings.TrimSpace(allowedSigner)) {
			return true
		}
	}
	return false
}

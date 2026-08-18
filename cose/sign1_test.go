package cose

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func TestVerifySign1(t *testing.T) {
	caKey, caCert := mustCreateCA(t)
	leafKey, leafCert := mustCreateCodeSigningLeaf(t, caKey, caCert, "Author Software Inc.")

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	SetChainVerifyRoots(roots)
	t.Cleanup(func() { SetChainVerifyRoots(nil) })

	inner := []byte("encrypted-inner-payload")
	signed := mustSignSign1(t, inner, leafKey, leafCert, caCert, iana.AlgorithmPS256)

	got, err := VerifySign1(signed, []string{"Author Software Inc."})
	if err != nil {
		t.Fatalf("VerifySign1() error = %v", err)
	}
	if string(got) != string(inner) {
		t.Fatalf("payload = %q, want %q", got, inner)
	}
}

func TestVerifySign1AcceptsExpiredAzureStyleLeaf(t *testing.T) {
	now := time.Now()
	caKey, caCert := mustCreateCAAt(t, now.Add(-72*time.Hour), now.Add(24*time.Hour))
	leafKey, leafCert := mustCreateCodeSigningLeafAt(t, caKey, caCert, "Author Software Inc.", now.Add(-48*time.Hour), now.Add(-23*time.Hour))

	if time.Now().Before(leafCert.NotAfter) {
		t.Fatal("test leaf must already be expired")
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	SetChainVerifyRoots(roots)
	t.Cleanup(func() { SetChainVerifyRoots(nil) })

	inner := []byte("encrypted-inner-payload")
	signed := mustSignSign1(t, inner, leafKey, leafCert, caCert, iana.AlgorithmPS256)

	got, err := VerifySign1(signed, []string{"Author Software Inc."})
	if err != nil {
		t.Fatalf("VerifySign1() expired leaf error = %v", err)
	}
	if string(got) != string(inner) {
		t.Fatalf("payload = %q, want %q", got, inner)
	}
}

func TestChainVerifyTimeRewindsExpiredLeaf(t *testing.T) {
	leaf := &x509.Certificate{
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	}
	got := chainVerifyTime(leaf, nil, nil)
	want := leaf.NotAfter.Add(-time.Second)
	if !got.Equal(want) {
		t.Fatalf("chainVerifyTime() = %v, want %v", got, want)
	}
}

func TestChainVerifyTimeUsesIatInsideLeafWindow(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-23 * time.Hour),
	}
	iat := now.Add(-30 * time.Hour).UTC().Truncate(time.Second)
	protected := cose.Headers{headerParameterIat: iat.Unix()}
	got := chainVerifyTime(leaf, protected, nil)
	if !got.Equal(iat) {
		t.Fatalf("chainVerifyTime() = %v, want iat %v", got, iat)
	}
}

func TestChainVerifyTimeIgnoresIatOutsideLeafWindow(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-23 * time.Hour),
	}
	protected := cose.Headers{headerParameterIat: now.Unix()}
	got := chainVerifyTime(leaf, protected, nil)
	want := leaf.NotAfter.Add(-time.Second)
	if !got.Equal(want) {
		t.Fatalf("chainVerifyTime() = %v, want rewind %v", got, want)
	}
}

func TestVerifySign1RejectsDisallowedSigner(t *testing.T) {
	caKey, caCert := mustCreateCA(t)
	leafKey, leafCert := mustCreateCodeSigningLeaf(t, caKey, caCert, "Author Software Inc.")

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	SetChainVerifyRoots(roots)
	t.Cleanup(func() { SetChainVerifyRoots(nil) })

	signed := mustSignSign1(t, []byte("payload"), leafKey, leafCert, caCert, iana.AlgorithmPS256)

	if _, err := VerifySign1(signed, []string{"Other Org"}); err == nil {
		t.Fatal("VerifySign1() error = nil, want disallowed signer failure")
	}
}

func TestVerifySign1RejectsUnsignedBlob(t *testing.T) {
	if _, err := VerifySign1([]byte("not-cose"), []string{"Author Software Inc."}); err == nil {
		t.Fatal("VerifySign1() error = nil, want failure")
	}
}

func TestVerifySign1RejectsTamperedPayload(t *testing.T) {
	caKey, caCert := mustCreateCA(t)
	leafKey, leafCert := mustCreateCodeSigningLeaf(t, caKey, caCert, "Author Software Inc.")

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	SetChainVerifyRoots(roots)
	t.Cleanup(func() { SetChainVerifyRoots(nil) })

	signed := mustSignSign1(t, []byte("good"), leafKey, leafCert, caCert, iana.AlgorithmPS256)
	signed[len(signed)-1] ^= 0xFF

	if _, err := VerifySign1(signed, []string{"Author Software Inc."}); err == nil {
		t.Fatal("VerifySign1() error = nil, want tamper failure")
	}
}

func TestCertificatesFromHeaderValue(t *testing.T) {
	_, caCert := mustCreateCA(t)
	certs, err := certificatesFromHeaderValue([]any{caCert.Raw})
	if err != nil {
		t.Fatalf("certificatesFromHeaderValue() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
}

func TestCertificateOrganization(t *testing.T) {
	caKey, caCert := mustCreateCA(t)
	_, leafCert := mustCreateCodeSigningLeaf(t, caKey, caCert, "Author Software Inc.")
	if got := certificateOrganization(leafCert); got != "Author Software Inc." {
		t.Fatalf("certificateOrganization() = %q", got)
	}
}

func mustCreateCA(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	return mustCreateCAAt(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

func mustCreateCAAt(t *testing.T, notBefore, notAfter time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return key, cert
}

func mustCreateCodeSigningLeaf(t *testing.T, caKey *rsa.PrivateKey, caCert *x509.Certificate, org string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	return mustCreateCodeSigningLeafAt(t, caKey, caCert, org, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

func mustCreateCodeSigningLeafAt(t *testing.T, caKey *rsa.PrivateKey, caCert *x509.Certificate, org string, notBefore, notAfter time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   org,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return key, cert
}

func mustSignSign1(t *testing.T, payload []byte, leafKey *rsa.PrivateKey, leafCert, caCert *x509.Certificate, alg int) []byte {
	t.Helper()

	x5chain := []any{leafCert.Raw, caCert.Raw}
	msg := &cose.Sign1Message[[]byte]{
		Protected: cose.Headers{
			iana.HeaderParameterAlg: alg,
		},
		Unprotected: cose.Headers{
			iana.HeaderParameterX5Chain: x5chain,
		},
		Payload: payload,
	}

	signer := &rsaTestSigner{priv: leafKey, alg: alg}
	if err := msg.WithSign(signer, ExternalAAD); err != nil {
		t.Fatalf("WithSign() error = %v", err)
	}

	out, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() error = %v", err)
	}

	return out
}

type rsaTestSigner struct {
	priv *rsa.PrivateKey
	alg  int
}

func (s *rsaTestSigner) Sign(data []byte) ([]byte, error) {
	hash, err := rsaHash(key.Alg(s.alg))
	if err != nil {
		return nil, err
	}
	digest, err := hashPayload(hash, data)
	if err != nil {
		return nil, err
	}

	switch s.alg {
	case iana.AlgorithmRS256, iana.AlgorithmRS384, iana.AlgorithmRS512:
		return rsa.SignPKCS1v15(rand.Reader, s.priv, hash, digest)
	case iana.AlgorithmPS256, iana.AlgorithmPS384, iana.AlgorithmPS512:
		return rsa.SignPSS(rand.Reader, s.priv, hash, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
	default:
		return nil, errors.New("unsupported test signing algorithm")
	}
}

func (s *rsaTestSigner) Key() key.Key {
	return key.Key{
		iana.KeyParameterKty: iana.KeyTypeRSA,
		iana.KeyParameterAlg: s.alg,
	}
}

package http

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyCertificateRejectsInvalidURL(t *testing.T) {
	cases := []string{
		"",
		"not-a-url",
		"http://example.com",
		"https://",
	}

	for _, raw := range cases {
		valid, reason := VerifyCertificate(raw)
		if valid {
			t.Fatalf("VerifyCertificate(%q) valid = true, want false", raw)
		}
		if strings.TrimSpace(reason) == "" {
			t.Fatalf("VerifyCertificate(%q) reason = empty, want explanation", raw)
		}
	}
}

func TestVerifyCertificateRejectsSelfSigned(t *testing.T) {
	cert := newSelfSignedCert(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	valid, reason := VerifyCertificate(server.URL)
	if valid {
		t.Fatal("VerifyCertificate(self-signed) valid = true, want false")
	}
	if reason == "" {
		t.Fatal("VerifyCertificate(self-signed) reason = empty, want validation failure")
	}
	if !strings.Contains(strings.ToLower(reason), "validation") && !strings.Contains(strings.ToLower(reason), "certificate") {
		t.Fatalf("VerifyCertificate(self-signed) reason = %q, want certificate validation failure", reason)
	}
}

func TestVerifyCertificateHandshakeFailureIsNotValid(t *testing.T) {
	valid, reason := VerifyCertificate("https://127.0.0.1:1")
	if valid {
		t.Fatal("VerifyCertificate(unreachable) valid = true, want false")
	}
	if reason == "" {
		t.Fatal("VerifyCertificate(unreachable) reason = empty, want handshake failure")
	}
	if !strings.Contains(strings.ToLower(reason), "handshake") {
		t.Fatalf("VerifyCertificate(unreachable) reason = %q, want handshake failure", reason)
	}
}

func newSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "verifycertificate-test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

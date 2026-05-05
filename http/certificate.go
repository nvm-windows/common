package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// VerifyCertificate retrieves and validates the TLS certificate for a HTTPS URL.
// It returns whether the certificate is valid and, when invalid, the reason.
func VerifyCertificate(rawURL string) (bool, string) {
	normalized, err := normalizeURL(rawURL)
	if err != nil {
		return false, "invalid URL: " + err.Error()
	}

	u, err := url.Parse(normalized)
	if err != nil {
		return false, "invalid URL: " + err.Error()
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return false, "URL must use https"
	}

	host := u.Hostname()
	if strings.TrimSpace(host) == "" {
		return false, "URL host is required"
	}

	port := u.Port()
	if port == "" {
		port = "443"
	}

	addr := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return false, "TLS handshake failed: " + err.Error()
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return false, "no peer certificate presented"
	}

	leaf := state.PeerCertificates[0]
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	})
	if err != nil {
		return false, fmt.Sprintf("certificate validation failed: %v", err)
	}

	return true, ""
}

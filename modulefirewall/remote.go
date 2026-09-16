package modulefirewall

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RemoteBlock describes a 403 row: name \t date \t reason
type RemoteBlock struct {
	Name   string
	Date   string
	Reason string
}

// RemoteResult is the outcome of EvaluateRemote.
type RemoteResult struct {
	Allowed  bool
	Status   int
	Blocks   []RemoteBlock
	ErrorMsg string
}

// RemoteTLSOptions configures HTTPS policy client behavior.
type RemoteTLSOptions struct {
	TimeoutSec         int
	AllowedOrgs        []string // TrustedFirewallSigners (O= match); empty = any valid CA chain
	AllowedThumbprints []string // TrustedFirewallThumbprint (SHA-1 leaf hex); empty = no pin
}

// EvaluateRemote POSTs newline-delimited module names to an HTTPS endpoint.
func EvaluateRemote(endpoint string, modules []PackageSpec, opts RemoteTLSOptions) RemoteResult {
	timeoutSec := opts.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 3
	}

	var body bytes.Buffer
	for _, m := range modules {
		line := m.Raw
		if line == "" {
			line = m.Name
			if m.Version != "" {
				line = m.Name + "@" + m.Version
			}
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		VerifyPeerCertificate: makePeerVerifier(opts.AllowedOrgs, opts.AllowedThumbprints),
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, &body)
	if err != nil {
		return RemoteResult{Allowed: false, ErrorMsg: fmt.Sprintf("firewall remote: bad request: %v", err)}
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "NVM-Windows-Firewall/1")

	res, err := client.Do(req)
	if err != nil {
		return RemoteResult{Allowed: false, ErrorMsg: fmt.Sprintf("firewall remote: request failed: %v", err)}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))

	switch res.StatusCode {
	case http.StatusOK:
		return RemoteResult{Allowed: true, Status: res.StatusCode}
	case http.StatusForbidden:
		return RemoteResult{
			Allowed:  false,
			Status:   res.StatusCode,
			Blocks:   parseForbiddenBody(string(raw)),
			ErrorMsg: "firewall remote: blocked by policy (HTTP 403)",
		}
	default:
		return RemoteResult{
			Allowed:  false,
			Status:   res.StatusCode,
			ErrorMsg: fmt.Sprintf("firewall remote: unexpected HTTP %d", res.StatusCode),
		}
	}
}

func makePeerVerifier(orgs, thumbs []string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	orgs = normalizePinList(orgs)
	thumbs = normalizeThumbList(thumbs)
	if len(orgs) == 0 && len(thumbs) == 0 {
		return nil
	}
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("firewall remote: empty peer certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("firewall remote: parse leaf: %w", err)
		}
		if len(thumbs) > 0 {
			sum := sha1.Sum(leaf.Raw)
			got := strings.ToLower(hex.EncodeToString(sum[:]))
			ok := false
			for _, want := range thumbs {
				if got == want {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("firewall remote: leaf thumbprint not in TrustedFirewallThumbprint")
			}
		}
		if len(orgs) > 0 {
			ok := false
			for _, o := range leaf.Subject.Organization {
				for _, want := range orgs {
					if strings.EqualFold(strings.TrimSpace(o), want) {
						ok = true
						break
					}
				}
				if ok {
					break
				}
			}
			if !ok {
				return fmt.Errorf("firewall remote: leaf O= not in TrustedFirewallSigners")
			}
		}
		_ = verifiedChains
		return nil
	}
}

func normalizePinList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func normalizeThumbList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
		s = strings.ReplaceAll(s, " ", "")
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseForbiddenBody(body string) []RemoteBlock {
	var blocks []RemoteBlock
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		b := RemoteBlock{}
		if len(parts) > 0 {
			b.Name = strings.TrimSpace(parts[0])
		}
		if len(parts) > 1 {
			b.Date = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			b.Reason = strings.TrimSpace(parts[2])
		}
		blocks = append(blocks, b)
	}
	return blocks
}

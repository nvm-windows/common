package modulefirewall

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
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

// EvaluateRemote POSTs newline-delimited module names to an HTTPS endpoint.
func EvaluateRemote(endpoint string, modules []PackageSpec, timeoutSec int, rootCAs *x509.CertPool, insecureSkipVerify bool) RemoteResult {
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

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            rootCAs,
				InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // only when policy explicitly allows
				MinVersion:         tls.VersionTLS12,
			},
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

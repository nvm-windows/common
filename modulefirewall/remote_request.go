package modulefirewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RemoteRequestOptions configures EvaluateRemote beyond TLS pins.
type RemoteRequestOptions struct {
	RemoteTLSOptions
	UserAgent     string
	Authorization string // full "Bearer …" or raw token
	Body          []byte
	ContentType   string
	ExtraHeaders  map[string]string
	SpinnerAfter  time.Duration // 0 = no spinner; e.g. 200ms for TTY stderr cue
}

// FirewallUserAgent builds `NVM for Windows/<version> <build>`.
// build should be "community" or "certified".
func FirewallUserAgent(version, build string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		version = "unknown"
	}
	version = strings.TrimPrefix(version, "v")
	build = strings.ToLower(strings.TrimSpace(build))
	if build == "" {
		build = "community"
	}
	return "NVM for Windows/" + version + " " + build
}

// EvaluateRemote POSTs package tokens or a custom body to an HTTPS policy endpoint.
func EvaluateRemote(endpoint string, modules []PackageSpec, opts RemoteTLSOptions) RemoteResult {
	return EvaluateRemoteRequest(endpoint, modules, RemoteRequestOptions{RemoteTLSOptions: opts})
}

// EvaluateRemoteRequest is EvaluateRemote with body/headers/JWT/UA control.
func EvaluateRemoteRequest(endpoint string, modules []PackageSpec, opts RemoteRequestOptions) RemoteResult {
	timeoutSec := opts.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 3
	}

	body := opts.Body
	contentType := strings.TrimSpace(opts.ContentType)
	if len(body) == 0 {
		var buf bytes.Buffer
		for _, m := range modules {
			line := m.Raw
			if line == "" {
				line = m.Name
				if m.Version != "" {
					line = m.Name + "@" + m.Version
				}
			}
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
		body = buf.Bytes()
		if contentType == "" {
			contentType = "text/plain; charset=utf-8"
		}
	}
	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}

	ua := strings.TrimSpace(opts.UserAgent)
	if ua == "" {
		ua = FirewallUserAgent("unknown", "certified")
	}

	tlsCfg := makeTLSConfig(opts.RemoteTLSOptions)

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return RemoteResult{Allowed: false, ErrorMsg: fmt.Sprintf("The NVM firewall could not build a request to the remote authority at %s.", displayRemoteAuthority(endpoint))}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", ua)
	if auth := strings.TrimSpace(opts.Authorization); auth != "" {
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			auth = "Bearer " + auth
		}
		req.Header.Set("Authorization", auth)
	}
	for k, v := range opts.ExtraHeaders {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		req.Header.Set(k, v)
	}

	stopSpinner := startRemoteSpinner(opts.SpinnerAfter)
	res, err := client.Do(req)
	stopSpinner()
	if err != nil {
		return remoteDialResult(endpoint, err)
	}
	defer res.Body.Close()
	raw, _ := readLimited(res.Body, 1<<20)

	switch res.StatusCode {
	case http.StatusOK:
		return RemoteResult{Allowed: true, Status: res.StatusCode}
	case http.StatusUnauthorized:
		return RemoteResult{
			Allowed:  false,
			Status:   res.StatusCode,
			ErrorMsg: fmt.Sprintf("The NVM firewall remote authority at %s denied access for this user.", displayRemoteAuthority(endpoint)),
		}
	case http.StatusForbidden:
		return RemoteResult{
			Allowed: false,
			Status:  res.StatusCode,
			Blocks:  parseForbiddenBody(string(raw)),
		}
	default:
		return RemoteResult{
			Allowed:  false,
			Status:   res.StatusCode,
			ErrorMsg: fmt.Sprintf("The NVM firewall remote authority at %s returned HTTP %d.", displayRemoteAuthority(endpoint), res.StatusCode),
		}
	}
}

func remoteDialResult(endpoint string, err error) RemoteResult {
	auth := displayRemoteAuthority(endpoint)
	if isRemoteUnreachableError(err) {
		return RemoteResult{
			Allowed:     false,
			Unreachable: true,
			ErrorMsg:    fmt.Sprintf("The NVM firewall could not reach the remote authority at %s because %s.", auth, humanizeRemoteDialReason(err)),
		}
	}
	return RemoteResult{
		Allowed:  false,
		ErrorMsg: fmt.Sprintf("The NVM firewall could not complete a request to the remote authority at %s.", auth),
	}
}

func displayRemoteAuthority(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "(unknown)"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return endpoint
	}
	if u.Path == "" || u.Path == "/" {
		return u.Scheme + "://" + u.Host
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func isRemoteUnreachableError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "x509") || strings.Contains(s, "certificate") || strings.Contains(s, "tls:") {
		return false
	}
	return strings.Contains(s, "refused") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "server misbehaving") ||
		strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "no route to host") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "forcibly closed")
}

func humanizeRemoteDialReason(err error) string {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return "the target machine actively refused it"
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded") || strings.Contains(s, "i/o timeout"):
		return "the connection timed out"
	case strings.Contains(s, "no such host") || strings.Contains(s, "server misbehaving"):
		return "the host could not be resolved"
	case strings.Contains(s, "network is unreachable") || strings.Contains(s, "no route to host"):
		return "the network is unreachable"
	case strings.Contains(s, "connection reset") || strings.Contains(s, "forcibly closed"):
		return "the connection was reset"
	default:
		return "the connection failed"
	}
}

// PackageJSONShasum returns hex SHA-256 of path, or empty on error.
func PackageJSONShasum(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ResolveProjectPackageJSON finds nearest package.json from cwd.
func ResolveProjectPackageJSON(cwd string) string {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return ""
	}
	p, _ := findNearestFile(abs, "package.json")
	return p
}

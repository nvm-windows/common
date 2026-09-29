package modulefirewall

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
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
	Allowed     bool
	Status      int
	Blocks      []RemoteBlock
	ErrorMsg    string
	Unreachable bool // dial/timeout/DNS — distinct from TLS/unexpected HTTP (NVM4409 vs NVM4402)
}

// RemoteTLSOptions configures HTTPS policy client behavior.
type RemoteTLSOptions struct {
	TimeoutSec         int
	AllowedOrgs        []string // TrustedFirewallSigners (O= match); empty = any valid CA chain
	AllowedThumbprints []string // TrustedFirewallThumbprint (SHA-1 leaf hex); empty = no pin
}

func makeTLSConfig(opts RemoteTLSOptions) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: makePeerVerifier(opts.AllowedOrgs, opts.AllowedThumbprints),
	}
}

func readLimited(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
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

const remotePolicyBlockedMsg = "blocked by remote policy"

// FormatRemoteUserMessage is the stderr text after "NVM Firewall: ".
// 200 never includes status. 403 is policy block. 401 is user unauthorized.
// Unreachable hosts use a short reachability sentence; other failures use ErrorMsg.
func FormatRemoteUserMessage(res RemoteResult) string {
	if res.Allowed || res.Status == http.StatusOK {
		return ""
	}
	if res.Status == http.StatusForbidden {
		return remotePolicyBlockedMsg
	}
	if res.Status == http.StatusUnauthorized {
		if strings.TrimSpace(res.ErrorMsg) != "" {
			return res.ErrorMsg
		}
		return "The NVM firewall remote authority denied access for this user."
	}
	if strings.TrimSpace(res.ErrorMsg) != "" {
		return res.ErrorMsg
	}
	return "The NVM firewall remote authority is unavailable or not responding."
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

// startRemoteSpinner prints a TTY stderr cue after delay; returned func clears it.
func startRemoteSpinner(after time.Duration) func() {
	if after <= 0 {
		return func() {}
	}
	fi, err := os.Stderr.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		return func() {}
	}

	var (
		mu      sync.Mutex
		shown   bool
		stopped bool
		done    = make(chan struct{})
	)
	go func() {
		t := time.NewTimer(after)
		defer t.Stop()
		select {
		case <-done:
			return
		case <-t.C:
		}
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		shown = true
		fmt.Fprint(os.Stderr, "\rrequesting approval...  ")
	}()

	return func() {
		close(done)
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		if shown {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
	}
}

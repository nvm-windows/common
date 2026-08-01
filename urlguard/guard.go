package urlguard

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateRemoteHTTPURL restricts http(s) targets to non-loopback, non-private hosts.
func ValidateRemoteHTTPURL(field, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%s URL is empty", field)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid URL: %w", field, raw, err)
	}

	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	switch scheme {
	case "http", "https":
	default:
		return fmt.Errorf("%s %q must use http or https", field, raw)
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("%s %q is not a valid URL (host is required)", field, raw)
	}

	if IsBlockedRemoteHost(host) {
		return fmt.Errorf("%s %q host %q is not allowed", field, raw, host)
	}

	return nil
}

// IsBlockedRemoteHost reports loopback, link-local, private, and unique-local hosts.
func IsBlockedRemoteHost(host string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	switch lower {
	case "localhost":
		return true
	}

	if ip := net.ParseIP(lower); ip != nil {
		return isBlockedRemoteIP(ip)
	}

	return false
}

func isBlockedRemoteIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}

	// Unique local (fc00::/7)
	if ip.To4() == nil && len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return true
	}

	return false
}

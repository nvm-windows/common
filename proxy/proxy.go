package proxy

import "net/http"

// WrapTransport returns the base RoundTripper unchanged.
// In the enterprise build, replace this module with common/proxy_pro via the go.mod
// replace directive to get transparent SSPI-backed NTLM/Negotiate proxy authentication.
func WrapTransport(base http.RoundTripper) http.RoundTripper {
	return base
}

// Credential returns the configured proxy credential for IWA proxies.
// Stub: always returns empty.
// Full implementation (proxy_pro) reads the credential from Windows Credential Manager.
func Credential() (string, error) {
	return "", nil
}

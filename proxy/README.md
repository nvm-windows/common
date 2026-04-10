# common/proxy

Standard build stub for proxy transport wrapping.

This module exposes the same API as `common/proxy_pro` but does nothing — it returns the HTTP transport unchanged and provides no credential support. It is the default for all standard (non-enterprise) builds of nvm-windows.

## API

```go
// WrapTransport returns the base RoundTripper unchanged.
func WrapTransport(base http.RoundTripper) http.RoundTripper

// Credential returns an empty string (no-op).
func Credential() (string, error)
```

## Switching to the enterprise build

To enable SSPI-backed NTLM/Negotiate proxy authentication, replace this module with `common/proxy_pro` in the consuming module's `go.mod`:

```
# Standard (default):
replace common/proxy v1.0.0 => ../common/proxy

# Enterprise:
replace common/proxy v1.0.0 => ../common/proxy_pro
```

No code changes are required — the API is identical between the two modules.

package http

import "testing"

func TestNormalizeProxyAddress(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: ""},
		{name: "with scheme", raw: "http://proxy.example.com:8080", want: "http://proxy.example.com:8080"},
		{name: "without scheme", raw: "proxy.example.com:8080", want: "http://proxy.example.com:8080"},
	}

	for _, test := range tests {
		if got := normalizeProxyAddress(test.raw); got != test.want {
			t.Fatalf("%s: expected %q, got %q", test.name, test.want, got)
		}
	}
}

func TestSelectProxyServer(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		scheme string
		want   string
	}{
		{name: "generic proxy", raw: "proxy.example.com:8080", scheme: "https", want: "proxy.example.com:8080"},
		{name: "http specific", raw: "http=proxy.example.com:8080;https=secure.example.com:8443", scheme: "http", want: "proxy.example.com:8080"},
		{name: "https specific", raw: "http=proxy.example.com:8080;https=secure.example.com:8443", scheme: "https", want: "secure.example.com:8443"},
		{name: "fallback to http", raw: "http=proxy.example.com:8080", scheme: "https", want: "proxy.example.com:8080"},
		{name: "empty", raw: "", scheme: "http", want: ""},
	}

	for _, test := range tests {
		if got := selectProxyServer(test.raw, test.scheme); got != test.want {
			t.Fatalf("%s: expected %q, got %q", test.name, test.want, got)
		}
	}
}

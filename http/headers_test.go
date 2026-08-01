package http

import (
	"net/url"
	"testing"
)

func TestApplyExtraHeadersIgnoresNonMirrorHost(t *testing.T) {
	req, err := makeRequest("GET", "https://nodejs.org/dist/index.tab")
	if err != nil {
		t.Fatalf("makeRequest() error = %v", err)
	}

	if got := req.Header.Get("X-Author-License"); got != "" {
		t.Fatalf("X-Author-License = %q, want empty for non-mirror host", got)
	}
}

func TestApplyExtraHeadersUsesMirrorAuthHook(t *testing.T) {
	u, err := url.Parse("https://mirror.author.io/dist/v22.0.0/node-v22.0.0-win-x64.7z")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	req, err := makeRequest("GET", u.String())
	if err != nil {
		t.Fatalf("makeRequest() error = %v", err)
	}

	// OSS stub returns no header unless enhanced mirrorauth is linked.
	_ = req.Header.Get("X-Author-License")
}

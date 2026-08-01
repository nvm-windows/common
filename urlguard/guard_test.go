package urlguard

import "testing"

func TestValidateRemoteHTTPURLRejectsPrivateHosts(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"http://127.0.0.1/test",
		"http://localhost/test",
		"http://10.0.0.5/test",
		"http://169.254.169.254/latest/meta-data",
	}

	for _, raw := range cases {
		if err := ValidateRemoteHTTPURL("url", raw); err == nil {
			t.Fatalf("ValidateRemoteHTTPURL(%q) error = nil, want rejection", raw)
		}
	}
}

func TestValidateRemoteHTTPURLAllowsHTTPSRemote(t *testing.T) {
	if err := ValidateRemoteHTTPURL("url", "https://nodejs.org/dist/index.tab"); err != nil {
		t.Fatalf("ValidateRemoteHTTPURL() error = %v", err)
	}
}

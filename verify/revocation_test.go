package verify

import "testing"

func TestParseRevocationMode(t *testing.T) {
	tests := []struct {
		raw  string
		want RevocationMode
	}{
		{"", RevocationOnline},
		{"online", RevocationOnline},
		{"cached", RevocationCached},
		{"cache-only", RevocationCached},
		{"disabled", RevocationDisabled},
		{"none", RevocationDisabled},
		{"bogus", RevocationOnline},
	}
	for _, tt := range tests {
		if got := ParseRevocationMode(tt.raw, RevocationOnline); got != tt.want {
			t.Fatalf("ParseRevocationMode(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestClampRuntimeRevocationMode(t *testing.T) {
	if got := ClampRuntimeRevocationMode(RevocationOnline); got != RevocationCached {
		t.Fatalf("online clamp = %q, want cached", got)
	}
	if got := ClampRuntimeRevocationMode(RevocationCached); got != RevocationCached {
		t.Fatalf("cached clamp = %q, want cached", got)
	}
	if got := ClampRuntimeRevocationMode(RevocationDisabled); got != RevocationDisabled {
		t.Fatalf("disabled clamp = %q, want disabled", got)
	}
}

func TestNormalizeThumbprint(t *testing.T) {
	got := NormalizeThumbprint("ab:cd ef-12")
	if got != "ABCDEF12" {
		t.Fatalf("NormalizeThumbprint = %q, want ABCDEF12", got)
	}
}

func TestIsAllowedThumbprint(t *testing.T) {
	if !IsAllowedThumbprint("ABCD", nil) {
		t.Fatal("empty pins should allow")
	}
	if !IsAllowedThumbprint("ab:cd", []string{"ABCD"}) {
		t.Fatal("expected pin match")
	}
	if IsAllowedThumbprint("ABCD", []string{"FFFF"}) {
		t.Fatal("expected pin reject")
	}
}

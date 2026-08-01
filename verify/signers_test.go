package verify

import (
	"strings"
	"testing"
)

func TestNormalizeAllowedSigners(t *testing.T) {
	got := normalizeAllowedSigners([]string{" OpenJS Foundation ", "", "Author Software Inc."})
	if len(got) != 2 {
		t.Fatalf("normalizeAllowedSigners() len = %d, want 2", len(got))
	}
	if got[0] != "OpenJS Foundation" || got[1] != "Author Software Inc." {
		t.Fatalf("normalizeAllowedSigners() = %#v", got)
	}
}

func TestIsAllowedSigner(t *testing.T) {
	allowed := []string{"OpenJS Foundation", "Author Software Inc."}

	if !isAllowedSigner("openjs foundation", allowed) {
		t.Fatal("isAllowedSigner() = false, want true for case-insensitive match")
	}
	if isAllowedSigner("Example Corp", allowed) {
		t.Fatal("isAllowedSigner() = true, want false for unknown signer")
	}
	if isAllowedSigner("  ", allowed) {
		t.Fatal("isAllowedSigner() = true, want false for blank signer")
	}
}

func TestEffectiveAllowedSignersUsesDefaultsWhenEmpty(t *testing.T) {
	got := EffectiveAllowedSigners(nil)
	if len(got) != len(DefaultAllowedSigners) {
		t.Fatalf("EffectiveAllowedSigners(nil) len = %d, want %d", len(got), len(DefaultAllowedSigners))
	}
	for i, want := range DefaultAllowedSigners {
		if got[i] != want {
			t.Fatalf("EffectiveAllowedSigners(nil)[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestVerifyNodeExecutableUsesDefaultAllowedSigners(t *testing.T) {
	_, err := VerifyNodeExecutable("C:\\does-not-matter.exe", nil)
	if err == nil {
		t.Fatal("VerifyNodeExecutable() error = nil, want error")
	}
	if strings.Contains(err.Error(), "no allowed code signers configured") {
		t.Fatalf("VerifyNodeExecutable() error = %q, want authenticode failure not empty-signer error", err.Error())
	}
}

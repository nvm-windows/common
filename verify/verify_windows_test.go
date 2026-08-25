//go:build windows

package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyNodeExecutableUnsignedFile(t *testing.T) {
	dir := t.TempDir()
	unsignedPath := filepath.Join(dir, "unsigned.bin")
	if err := os.WriteFile(unsignedPath, []byte("not a signed executable"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := VerifyNodeExecutableWithOptions(unsignedPath, Options{
		AllowedSigners:     []string{"OpenJS Foundation"},
		Revocation:         RevocationDisabled,
		AllowedThumbprints: []string{},
	})
	if err == nil {
		t.Fatal("VerifyNodeExecutable() error = nil, want authenticode failure")
	}
	if !strings.Contains(err.Error(), "authenticode signature verification failed") {
		t.Fatalf("VerifyNodeExecutable() error = %q", err.Error())
	}
}

func TestVerifyNodeExecutableMissingFile(t *testing.T) {
	_, err := VerifyNodeExecutableWithOptions(filepath.Join(t.TempDir(), "missing.exe"), Options{
		AllowedSigners:     []string{"OpenJS Foundation"},
		Revocation:         RevocationDisabled,
		AllowedThumbprints: []string{},
	})
	if err == nil {
		t.Fatal("VerifyNodeExecutable() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unable to verify authenticode signature") {
		t.Fatalf("VerifyNodeExecutable() error = %q", err.Error())
	}
}

func embeddedSignedNodeExecutable(t *testing.T) string {
	t.Helper()

	if override := strings.TrimSpace(os.Getenv("NVM_TEST_SIGNED_NODE")); override != "" {
		if _, statErr := os.Stat(override); statErr == nil {
			return override
		}
		t.Fatalf("NVM_TEST_SIGNED_NODE=%q is not accessible", override)
	}

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		t.Skip("LOCALAPPDATA is not set")
	}

	matches, err := filepath.Glob(filepath.Join(localAppData, "Author Software", "nvm", "installs", "*", "node.exe"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	for _, candidate := range matches {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	t.Skip("no embedded-signed node.exe found; set NVM_TEST_SIGNED_NODE to run this test")
	return ""
}

func TestVerifyNodeExecutableSignedNodeBinary(t *testing.T) {
	nodePath := embeddedSignedNodeExecutable(t)

	signer, err := VerifyNodeExecutableWithOptions(nodePath, Options{
		AllowedSigners:     []string{"OpenJS Foundation", "Node.js Foundation"},
		Revocation:         RevocationCached,
		AllowedThumbprints: []string{},
	})
	if err != nil {
		t.Fatalf("VerifyNodeExecutable(%q) error = %v", nodePath, err)
	}
	if strings.TrimSpace(signer) == "" {
		t.Fatal("VerifyNodeExecutable() signer = empty, want organization name")
	}
}

func TestVerifyNodeExecutableRejectsDisallowedSigner(t *testing.T) {
	nodePath := embeddedSignedNodeExecutable(t)

	_, err := VerifyNodeExecutableWithOptions(nodePath, Options{
		AllowedSigners:     []string{"Microsoft Windows"},
		Revocation:         RevocationCached,
		AllowedThumbprints: []string{},
	})
	if err == nil {
		t.Fatal("VerifyNodeExecutable() error = nil, want disallowed signer error")
	}
	if !strings.Contains(err.Error(), "is not allowed") {
		t.Fatalf("VerifyNodeExecutable() error = %q", err.Error())
	}
}

func TestVerifyNodeExecutableRejectsUnpinnedThumbprint(t *testing.T) {
	nodePath := embeddedSignedNodeExecutable(t)

	_, err := VerifyNodeExecutableWithOptions(nodePath, Options{
		AllowedSigners:     []string{"OpenJS Foundation", "Node.js Foundation"},
		Revocation:         RevocationCached,
		AllowedThumbprints: []string{"0000000000000000000000000000000000000000"},
	})
	if err == nil {
		t.Fatal("VerifyNodeExecutable() error = nil, want thumbprint pin failure")
	}
	if !strings.Contains(err.Error(), "is not pinned") {
		t.Fatalf("VerifyNodeExecutable() error = %q", err.Error())
	}
}

func TestVerifyNodeExecutableAcceptsPinnedThumbprint(t *testing.T) {
	nodePath := embeddedSignedNodeExecutable(t)
	thumb := SignerThumbprint(nodePath)
	if thumb == "" {
		t.Fatal("SignerThumbprint empty")
	}

	_, err := VerifyNodeExecutableWithOptions(nodePath, Options{
		AllowedSigners:     []string{"OpenJS Foundation", "Node.js Foundation"},
		Revocation:         RevocationCached,
		AllowedThumbprints: []string{thumb},
	})
	if err != nil {
		t.Fatalf("VerifyNodeExecutable() with matching pin error = %v", err)
	}
}

func TestSignerOrganizationReturnsEmbeddedSigner(t *testing.T) {
	nodePath := embeddedSignedNodeExecutable(t)

	signer := SignerOrganization(nodePath)
	if signer == "" {
		t.Fatalf("SignerOrganization(%q) = empty, want signer name", nodePath)
	}
	if !strings.Contains(strings.ToLower(signer), "openjs") {
		t.Fatalf("SignerOrganization(%q) = %q, want OpenJS-related signer", nodePath, signer)
	}
}

func BenchmarkVerifyNodeExecutableCached(b *testing.B) {
	nodePath := embeddedSignedNodeExecutableBench(b)
	opts := Options{
		AllowedSigners:     []string{"OpenJS Foundation", "Node.js Foundation", "Author Software Inc."},
		Revocation:         RevocationCached,
		AllowedThumbprints: []string{},
	}
	if _, err := VerifyNodeExecutableWithOptions(nodePath, opts); err != nil {
		b.Fatalf("warmup: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyNodeExecutableWithOptions(nodePath, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyNodeExecutableDisabled(b *testing.B) {
	nodePath := embeddedSignedNodeExecutableBench(b)
	opts := Options{
		AllowedSigners:     []string{"OpenJS Foundation", "Node.js Foundation", "Author Software Inc."},
		Revocation:         RevocationDisabled,
		AllowedThumbprints: []string{},
	}
	if _, err := VerifyNodeExecutableWithOptions(nodePath, opts); err != nil {
		b.Fatalf("warmup: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyNodeExecutableWithOptions(nodePath, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyNodeExecutableOnline(b *testing.B) {
	nodePath := embeddedSignedNodeExecutableBench(b)
	opts := Options{
		AllowedSigners:     []string{"OpenJS Foundation", "Node.js Foundation", "Author Software Inc."},
		Revocation:         RevocationOnline,
		AllowedThumbprints: []string{},
	}
	if _, err := VerifyNodeExecutableWithOptions(nodePath, opts); err != nil {
		b.Skipf("online revocation unavailable: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyNodeExecutableWithOptions(nodePath, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func embeddedSignedNodeExecutableBench(b *testing.B) string {
	b.Helper()
	if override := strings.TrimSpace(os.Getenv("NVM_TEST_SIGNED_NODE")); override != "" {
		if _, err := os.Stat(override); err == nil {
			return override
		}
		b.Fatalf("NVM_TEST_SIGNED_NODE=%q is not accessible", override)
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		b.Skip("LOCALAPPDATA is not set")
	}
	matches, err := filepath.Glob(filepath.Join(localAppData, "Author Software", "nvm", "installs", "*", "node.exe"))
	if err != nil {
		b.Fatalf("Glob() error = %v", err)
	}
	for _, candidate := range matches {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	b.Skip("no embedded-signed node.exe found; set NVM_TEST_SIGNED_NODE")
	return ""
}

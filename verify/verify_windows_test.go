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

	_, err := VerifyNodeExecutable(unsignedPath, []string{"OpenJS Foundation"})
	if err == nil {
		t.Fatal("VerifyNodeExecutable() error = nil, want authenticode failure")
	}
	if !strings.Contains(err.Error(), "authenticode signature verification failed") {
		t.Fatalf("VerifyNodeExecutable() error = %q", err.Error())
	}
}

func TestVerifyNodeExecutableMissingFile(t *testing.T) {
	_, err := VerifyNodeExecutable(filepath.Join(t.TempDir(), "missing.exe"), []string{"OpenJS Foundation"})
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

	signer, err := VerifyNodeExecutable(nodePath, []string{"OpenJS Foundation", "Node.js Foundation"})
	if err != nil {
		t.Fatalf("VerifyNodeExecutable(%q) error = %v", nodePath, err)
	}
	if strings.TrimSpace(signer) == "" {
		t.Fatal("VerifyNodeExecutable() signer = empty, want organization name")
	}
}

func TestVerifyNodeExecutableRejectsDisallowedSigner(t *testing.T) {
	nodePath := embeddedSignedNodeExecutable(t)

	_, err := VerifyNodeExecutable(nodePath, []string{"Microsoft Windows"})
	if err == nil {
		t.Fatal("VerifyNodeExecutable() error = nil, want disallowed signer error")
	}
	if !strings.Contains(err.Error(), "is not allowed") {
		t.Fatalf("VerifyNodeExecutable() error = %q", err.Error())
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

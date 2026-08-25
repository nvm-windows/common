//go:build windows

package verifycache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExportVerifyCacheFixtures(t *testing.T) {
	if os.Getenv("EXPORT_VERIFYCACHE_FIXTURES") == "" {
		t.Skip("set EXPORT_VERIFYCACHE_FIXTURES=1 to write shim test fixtures")
	}

	dataRoot := t.TempDir()
	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey() error = %v", err)
	}

	pubKey, err := os.ReadFile(PubKeyPath(dataRoot))
	if err != nil {
		t.Fatalf("ReadFile(pubkey) error = %v", err)
	}

	const (
		nodePath   = `C:\nvm\installs\v22\node.exe`
		size       = int64(12345)
		mtime      = uint64(9876543210)
		thumbprint = "ABCD1234"
		digest     = "aabbccdd"
	)
	state := fileSecurityState{VolumeSerial: 42, FileID: 123, USN: 456}

	payload, err := canonicalPayload(nodePath, size, mtime, thumbprint, digest, state)
	if err != nil {
		t.Fatalf("canonicalPayload() error = %v", err)
	}

	containerName, err := loadKeyContainerName(dataRoot)
	if err != nil {
		t.Fatalf("loadKeyContainerName() error = %v", err)
	}

	key, err := openPersistedKey(containerName)
	if err != nil {
		t.Fatalf("openPersistedKey() error = %v", err)
	}
	defer key.Close()

	signature, err := signPayload(key, []byte(payload))
	if err != nil {
		t.Fatalf("signPayload() error = %v", err)
	}

	if err := verifyCacheSignature(pubKey, []byte(payload), signature); err != nil {
		t.Fatalf("verifyCacheSignature() error = %v", err)
	}

	fixtureDir := filepath.Clean(filepath.Join("..", "..", "shim", "testdata", "verifycache"))
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(fixtureDir) error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(fixtureDir, "pubkey.cer"), pubKey, 0o644); err != nil {
		t.Fatalf("WriteFile(pubkey.cer) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "payload.txt"), []byte(payload), 0o644); err != nil {
		t.Fatalf("WriteFile(payload.txt) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "signature.bin"), signature, 0o644); err != nil {
		t.Fatalf("WriteFile(signature.bin) error = %v", err)
	}
}

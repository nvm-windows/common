//go:build windows

package verifycache

import (
	"os"
	"testing"
)

func setupDI01Bench(b *testing.B) (dataRoot string, payload, signature []byte) {
	b.Helper()
	dataRoot = b.TempDir()
	if err := EnsureVerifyKey(dataRoot); err != nil {
		b.Fatalf("EnsureVerifyKey: %v", err)
	}
	payload = []byte("di01-bench-payload-v3-identity-bound")
	keyName, err := loadKeyContainerName(dataRoot)
	if err != nil {
		b.Fatalf("loadKeyContainerName: %v", err)
	}
	key, err := openPersistedKey(keyName)
	if err != nil {
		b.Fatalf("openPersistedKey: %v", err)
	}
	defer key.Close()
	signature, err = signPayload(key, payload)
	if err != nil {
		b.Fatalf("signPayload: %v", err)
	}
	return dataRoot, payload, signature
}

// Current warm path: disk pubkey.cer + BCrypt import/verify.
func BenchmarkDI01_BCryptFilePubKey(b *testing.B) {
	dataRoot, payload, signature := setupDI01Bench(b)
	pubPath := PubKeyPath(dataRoot)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blob, err := os.ReadFile(pubPath)
		if err != nil {
			b.Fatal(err)
		}
		if err := verifyCacheSignature(blob, payload, signature); err != nil {
			b.Fatal(err)
		}
	}
}

// Option A: NCrypt open persisted key + NCryptVerifySignature (no pubkey.cer).
func BenchmarkDI01_NCryptPersistedKey(b *testing.B) {
	dataRoot, payload, signature := setupDI01Bench(b)
	keyName, err := loadKeyContainerName(dataRoot)
	if err != nil {
		b.Fatal(err)
	}
	// Include reading key-container.txt like Zig would.
	containerPath := KeyContainerPath(dataRoot)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nameBytes, err := os.ReadFile(containerPath)
		if err != nil && !os.IsNotExist(err) {
			b.Fatal(err)
		}
		_ = nameBytes
		key, err := openPersistedKey(keyName)
		if err != nil {
			b.Fatal(err)
		}
		err = verifySignatureWithKey(key, payload, signature)
		key.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Option C add-on: fingerprint pubkey.cer (SHA-256) vs stored 32-byte digest.
func BenchmarkDI01_PubKeyFingerprintOnly(b *testing.B) {
	dataRoot, _, _ := setupDI01Bench(b)
	pubPath := PubKeyPath(dataRoot)
	blob, err := os.ReadFile(pubPath)
	if err != nil {
		b.Fatal(err)
	}
	want := hashPayload(blob)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gotBlob, err := os.ReadFile(pubPath)
		if err != nil {
			b.Fatal(err)
		}
		got := hashPayload(gotBlob)
		if got != want {
			b.Fatal("fingerprint mismatch")
		}
	}
}

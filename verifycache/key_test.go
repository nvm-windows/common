//go:build windows

package verifycache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureVerifyKeyCreatesPubKey(t *testing.T) {
	dataRoot := t.TempDir()

	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey() error = %v", err)
	}

	pubKeyPath := PubKeyPath(dataRoot)
	info, err := os.Stat(pubKeyPath)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", pubKeyPath, err)
	}
	if info.Size() == 0 {
		t.Fatalf("Stat(%q) size = 0, want exported public key bytes", pubKeyPath)
	}

	containerPath := KeyContainerPath(dataRoot)
	containerData, err := os.ReadFile(containerPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", containerPath, err)
	}
	if len(containerData) == 0 {
		t.Fatal("key-container.txt is empty")
	}
}

func TestEnsureVerifyKeyIdempotent(t *testing.T) {
	dataRoot := t.TempDir()

	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey(first) error = %v", err)
	}

	first, err := os.ReadFile(PubKeyPath(dataRoot))
	if err != nil {
		t.Fatalf("ReadFile(first pubkey) error = %v", err)
	}

	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey(second) error = %v", err)
	}

	second, err := os.ReadFile(PubKeyPath(dataRoot))
	if err != nil {
		t.Fatalf("ReadFile(second pubkey) error = %v", err)
	}

	if string(first) != string(second) {
		t.Fatal("EnsureVerifyKey() rewrote pubkey.cer on second run")
	}
}

func TestEnsureVerifyKeyRepairsMissingPubKey(t *testing.T) {
	dataRoot := t.TempDir()

	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey(initial) error = %v", err)
	}

	pubKeyPath := PubKeyPath(dataRoot)
	if err := os.Remove(pubKeyPath); err != nil {
		t.Fatalf("Remove(pubkey) error = %v", err)
	}

	if err := EnsureVerifyKey(dataRoot); err != nil {
		t.Fatalf("EnsureVerifyKey(repair) error = %v", err)
	}

	if _, err := os.Stat(pubKeyPath); err != nil {
		t.Fatalf("Stat(repaired pubkey) error = %v", err)
	}
}

func TestDirPaths(t *testing.T) {
	dataRoot := filepath.Clean(`C:\Users\test\AppData\Local\Author Software\nvm`)
	if got := Dir(dataRoot); got != dataRoot+`\`+verifyDirName && got != dataRoot+`/`+verifyDirName {
		// filepath.Join normalizes to backslash on Windows
		want := filepath.Join(dataRoot, verifyDirName)
		if got != want {
			t.Fatalf("Dir() = %q, want %q", got, want)
		}
	}
}

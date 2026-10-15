//go:build windows

package verifycache

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifyKeyStoreErrorNamesCodeAndSecuritySoftware(t *testing.T) {
	err := &VerifyKeyStoreError{
		KeyName:       defaultKeyName,
		Attempts:      verifyKeyOpenAttempts,
		Provider:      msSoftwareKeyProvider,
		Status:        0x80090016,
		PubKeyPresent: true,
	}
	text := err.Error()
	for _, needle := range []string{
		defaultKeyName,
		"0x80090016",
		msSoftwareKeyProvider,
		"Security software",
		"nvm reshim",
		"Event code: NVM4312",
		"public key file is present",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("error text missing %q:\n%s", needle, text)
		}
	}
	if err.Code() != CodeVerifyKeyStore {
		t.Fatalf("Code() = %d", err.Code())
	}
}

func TestOpenPersistedKeyRetrySucceedsAfterTransientFailure(t *testing.T) {
	origOpen := openPersistedKeyAttempt
	origSleep := verifyKeyOpenSleep
	t.Cleanup(func() {
		openPersistedKeyAttempt = origOpen
		verifyKeyOpenSleep = origSleep
	})

	calls := 0
	var slept []time.Duration
	verifyKeyOpenSleep = func(d time.Duration) { slept = append(slept, d) }
	openPersistedKeyAttempt = func(string) (verifyKey, persistedKeyAttempt, error) {
		calls++
		if calls < 3 {
			return verifyKey{}, persistedKeyAttempt{Provider: msSoftwareKeyProvider, Status: 0x80090016}, errVerifyKeyNotOpen
		}
		return verifyKey{}, persistedKeyAttempt{}, nil
	}

	key, err := openPersistedKeyRetry(defaultKeyName)
	if err != nil {
		t.Fatalf("openPersistedKeyRetry() error = %v", err)
	}
	key.Close()
	if calls != 3 {
		t.Fatalf("attempts = %d, want 3", calls)
	}
	if len(slept) != 2 || slept[0] != 100*time.Millisecond || slept[1] != 200*time.Millisecond {
		t.Fatalf("sleeps = %v", slept)
	}
}

func TestOpenSigningKeyReportsAfterRetries(t *testing.T) {
	origOpen := openPersistedKeyAttempt
	origSleep := verifyKeyOpenSleep
	origEmit := emitVerifyKeyStoreEvent
	t.Cleanup(func() {
		openPersistedKeyAttempt = origOpen
		verifyKeyOpenSleep = origSleep
		emitVerifyKeyStoreEvent = origEmit
	})

	verifyKeyOpenSleep = func(time.Duration) {}
	openPersistedKeyAttempt = func(string) (verifyKey, persistedKeyAttempt, error) {
		return verifyKey{}, persistedKeyAttempt{Provider: msPlatformCryptoProvider, Status: 0x80090016}, errVerifyKeyNotOpen
	}
	var got *VerifyKeyStoreError
	emitVerifyKeyStoreEvent = func(store *VerifyKeyStoreError) { got = store }

	dir := t.TempDir()
	_, err := openSigningKey(dir, defaultKeyName)
	var store *VerifyKeyStoreError
	if !errors.As(err, &store) {
		t.Fatalf("error = %T %v", err, err)
	}
	if store.Attempts != verifyKeyOpenAttempts {
		t.Fatalf("attempts = %d", store.Attempts)
	}
	if store.PubKeyPresent {
		t.Fatal("pubkey should be absent")
	}
	if got == nil || got.Status != 0x80090016 {
		t.Fatalf("emitted %#v", got)
	}
	if !strings.Contains(err.Error(), "public key file is missing") {
		t.Fatalf("text = %s", err.Error())
	}
}

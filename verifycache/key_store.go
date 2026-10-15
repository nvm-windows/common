//go:build windows

package verifycache

import (
	"common/eventlog"
	"common/system"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"
)

// CodeVerifyKeyStore is NVM4312: the NCrypt verify key did not open.
const CodeVerifyKeyStore = 4312

const verifyKeyOpenEvent = "verify_key.open_failed"

const verifyKeyOpenAttempts = 4

const verifyKeyCommonCause = "security software locked or blocked ncrypt"

var errVerifyKeyNotOpen = errors.New("verify key did not open")

var verifyKeyOpenSleep = time.Sleep

// openPersistedKeyAttempt opens the key once. Tests replace this.
var openPersistedKeyAttempt = openPersistedKeyNCrypt

type persistedKeyAttempt struct {
	Provider string
	Status   uint32
	Detail   string
}

// VerifyKeyStoreError is the user-facing NVM4312 failure after retries.
type VerifyKeyStoreError struct {
	KeyName       string
	Attempts      int
	Provider      string
	Status        uint32
	Detail        string
	PubKeyPresent bool
}

func (e *VerifyKeyStoreError) Error() string {
	if e == nil {
		return "Could not open the verify signing key.\nEvent code: NVM4312"
	}
	provider := strings.TrimSpace(e.Provider)
	if provider == "" {
		provider = "unknown"
	}
	status := "unavailable"
	if e.Status != 0 {
		status = fmt.Sprintf("0x%08X", e.Status)
	}
	keyName := strings.TrimSpace(e.KeyName)
	if keyName == "" {
		keyName = defaultKeyName
	}
	pubkey := "The public key file is missing."
	if e.PubKeyPresent {
		pubkey = "The public key file is present, so this key was not deleted."
	}
	return fmt.Sprintf(
		"Could not open verify key %q after %d attempts. Provider: %s. Status: %s. %s %s Run nvm reshim again. If the error remains, allow nvm.exe and reshim.exe to use the Microsoft Software Key Storage Provider and key container %s.\nEvent code: NVM%d",
		keyName,
		e.Attempts,
		provider,
		status,
		pubkey,
		system.AntivirusConflictSentence(),
		keyName,
		CodeVerifyKeyStore,
	)
}

func (e *VerifyKeyStoreError) Code() int {
	return CodeVerifyKeyStore
}

func newVerifyKeyStoreError(keyName string, attempts int, last persistedKeyAttempt) *VerifyKeyStoreError {
	if attempts < 1 {
		attempts = 1
	}
	return &VerifyKeyStoreError{
		KeyName:  keyName,
		Attempts: attempts,
		Provider: last.Provider,
		Status:   last.Status,
		Detail:   last.Detail,
	}
}

func verifyKeyOpenDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	shift := attempt - 1
	if shift > 4 {
		shift = 4
	}
	return time.Duration(100*(1<<shift)) * time.Millisecond
}

// openPersistedKey opens the key once. Key creation uses this so a missing key
// does not wait through the signing retries.
func openPersistedKey(keyName string) (verifyKey, error) {
	key, attempt, err := openPersistedKeyAttempt(keyName)
	if err == nil {
		return key, nil
	}
	return verifyKey{}, newVerifyKeyStoreError(keyName, 1, attempt)
}

func openPersistedKeyRetry(keyName string) (verifyKey, error) {
	var last persistedKeyAttempt
	for attempt := 0; attempt < verifyKeyOpenAttempts; attempt++ {
		if delay := verifyKeyOpenDelay(attempt); delay > 0 {
			verifyKeyOpenSleep(delay)
		}
		key, got, err := openPersistedKeyAttempt(keyName)
		if err == nil {
			return key, nil
		}
		last = got
	}
	return verifyKey{}, newVerifyKeyStoreError(keyName, verifyKeyOpenAttempts, last)
}

// openSigningKey retries, then reports NVM4312 when the key still does not open.
func openSigningKey(dataRoot, keyName string) (verifyKey, error) {
	key, err := openPersistedKeyRetry(keyName)
	if err != nil {
		return verifyKey{}, reportVerifyKeyStore(dataRoot, err)
	}
	return key, nil
}

func reportVerifyKeyStore(dataRoot string, err error) error {
	var store *VerifyKeyStoreError
	if !errors.As(err, &store) {
		return err
	}
	if _, statErr := os.Stat(PubKeyPath(dataRoot)); statErr == nil {
		store.PubKeyPresent = true
	}
	emitVerifyKeyStoreEvent(store)
	return store
}

var emitVerifyKeyStoreEvent = emitVerifyKeyStorePlain

// SetCertifiedVerifyKeyLogging selects the certified SIEM event for NVM4312.
// Community builds keep the classic operational error.
func SetCertifiedVerifyKeyLogging(enabled bool) {
	if enabled {
		emitVerifyKeyStoreEvent = emitVerifyKeyStoreStructured
		return
	}
	emitVerifyKeyStoreEvent = emitVerifyKeyStorePlain
}

func emitVerifyKeyStorePlain(store *VerifyKeyStoreError) {
	if store == nil {
		return
	}
	eventlog.Error(store, CodeVerifyKeyStore)
}

func emitVerifyKeyStoreStructured(store *VerifyKeyStoreError) {
	if store == nil {
		return
	}
	eventlog.ErrorStructured(verifyKeyOpenEvent, verifyKeyStorePayload(store), CodeVerifyKeyStore)
}

func verifyKeyStorePayload(store *VerifyKeyStoreError) map[string]any {
	status := "unavailable"
	if store.Status != 0 {
		status = fmt.Sprintf("0x%08X", store.Status)
	}
	provider := strings.TrimSpace(store.Provider)
	if provider == "" {
		provider = "unknown"
	}
	keyName := strings.TrimSpace(store.KeyName)
	if keyName == "" {
		keyName = defaultKeyName
	}
	userName, sid, host := verifyKeyAuditIdentity()
	return map[string]any{
		"key_name":       keyName,
		"provider":       provider,
		"status":         status,
		"attempts":       store.Attempts,
		"pubkey_present": store.PubKeyPresent,
		"common_cause":   verifyKeyCommonCause,
		"antivirus":      system.AntivirusLabel(),
		"resolution":     "Run nvm reshim again. If the error remains, allow nvm.exe and reshim.exe to use the Microsoft Software Key Storage Provider and this key container.",
		"detail":         store.Detail,
		"user":           userName,
		"sid":            sid,
		"hostname":       host,
		"correlation_id": verifyKeyCorrelationID(),
	}
}

func verifyKeyAuditIdentity() (userName, sid, host string) {
	userName = "unknown"
	sid = "unknown"
	host = "unknown"
	if current, err := user.Current(); err == nil {
		if name := strings.TrimSpace(current.Username); name != "" {
			userName = name
		}
		if id := strings.TrimSpace(current.Uid); id != "" {
			sid = id
		}
	}
	if name, err := os.Hostname(); err == nil {
		if name = strings.TrimSpace(name); name != "" {
			host = name
		}
	}
	return userName, sid, host
}

func verifyKeyCorrelationID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

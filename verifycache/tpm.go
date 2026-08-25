//go:build windows

package verifycache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"
	msSoftwareKeyProvider    = "Microsoft Software Key Storage Provider"
	msPrimitiveProvider      = "Microsoft Primitive Provider"
	bcryptECDSA_P256         = "ECDSA_P256"
	bcryptECCPublicBlob      = "ECCPUBLICBLOB"
)

var (
	ncrypt                         = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider  = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptFreeObject           = ncrypt.NewProc("NCryptFreeObject")
	procNCryptCreatePersistedKey   = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptFinalizeKey        = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptOpenKey              = ncrypt.NewProc("NCryptOpenKey")
	procNCryptExportKey            = ncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash             = ncrypt.NewProc("NCryptSignHash")
	procNCryptVerifySignature      = ncrypt.NewProc("NCryptVerifySignature")
)

type verifyKey struct {
	handle windows.Handle
}

func (k verifyKey) Close() {
	if k.handle != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(k.handle))
	}
}

func provisionKey(keyName string) (verifyKey, string, error) {
	keyName = strings.TrimSpace(keyName)
	if keyName == "" {
		keyName = defaultKeyName
	}

	if key, err := openPersistedKey(keyName); err == nil {
		return key, "", nil
	}

	for _, providerName := range []string{msPlatformCryptoProvider, msSoftwareKeyProvider} {
		key, err := createPersistedKey(providerName, keyName)
		if err == nil {
			return key, providerName, nil
		}
	}

	return verifyKey{}, "", fmt.Errorf("failed to provision verify signing key %q", keyName)
}

func exportPublicKey(key verifyKey, pubKeyPath string) error {
	if key.handle == 0 {
		return fmt.Errorf("verify key handle is invalid")
	}

	blob, err := exportECCPublicBlob(key.handle)
	if err != nil {
		return err
	}

	tempPath := pubKeyPath + ".tmp"
	if err := os.WriteFile(tempPath, blob, 0o644); err != nil {
		return fmt.Errorf("failed to write temporary public key: %w", err)
	}

	if err := os.Remove(pubKeyPath); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to replace existing public key: %w", err)
	}

	if err := os.Rename(tempPath, pubKeyPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to install public key: %w", err)
	}

	// DI-01 C: fingerprint written only on NCrypt export path.
	dataRoot := filepath.Dir(filepath.Dir(pubKeyPath))
	if err := writePubKeyFingerprint(dataRoot, blob); err != nil {
		return err
	}

	return nil
}

func openPersistedKey(keyName string) (verifyKey, error) {
	for _, providerName := range []string{msPlatformCryptoProvider, msSoftwareKeyProvider} {
		provider, err := openProvider(providerName)
		if err != nil {
			continue
		}

		keyNameW, err := windows.UTF16PtrFromString(keyName)
		if err != nil {
			provider.Close()
			return verifyKey{}, err
		}

		var keyHandle windows.Handle
		r, _, callErr := procNCryptOpenKey.Call(
			uintptr(provider.handle),
			uintptr(unsafe.Pointer(&keyHandle)),
			uintptr(unsafe.Pointer(keyNameW)),
			0,
			0,
		)
		provider.Close()
		if r != 0 {
			if callErr != syscall.Errno(0) && callErr != nil {
				continue
			}
			continue
		}

		return verifyKey{handle: keyHandle}, nil
	}

	return verifyKey{}, fmt.Errorf("persisted verify key %q not found", keyName)
}

func createPersistedKey(providerName, keyName string) (verifyKey, error) {
	provider, err := openProvider(providerName)
	if err != nil {
		return verifyKey{}, err
	}
	defer provider.Close()

	algW, err := windows.UTF16PtrFromString(bcryptECDSA_P256)
	if err != nil {
		return verifyKey{}, err
	}
	keyNameW, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return verifyKey{}, err
	}

	var keyHandle windows.Handle
	r, _, callErr := procNCryptCreatePersistedKey.Call(
		uintptr(provider.handle),
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(algW)),
		uintptr(unsafe.Pointer(keyNameW)),
		0,
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return verifyKey{}, fmt.Errorf("NCryptCreatePersistedKey failed: %w", callErr)
		}
		return verifyKey{}, fmt.Errorf("NCryptCreatePersistedKey failed with status 0x%x", r)
	}

	r, _, callErr = procNCryptFinalizeKey.Call(uintptr(keyHandle), 0)
	if r != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(keyHandle))
		if callErr != syscall.Errno(0) && callErr != nil {
			return verifyKey{}, fmt.Errorf("NCryptFinalizeKey failed: %w", callErr)
		}
		return verifyKey{}, fmt.Errorf("NCryptFinalizeKey failed with status 0x%x", r)
	}

	return verifyKey{handle: keyHandle}, nil
}

type providerHandle struct {
	handle windows.Handle
}

func (p providerHandle) Close() {
	if p.handle != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(p.handle))
	}
}

func openProvider(name string) (providerHandle, error) {
	nameW, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return providerHandle{}, err
	}

	var handle windows.Handle
	r, _, callErr := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(nameW)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return providerHandle{}, fmt.Errorf("NCryptOpenStorageProvider(%s) failed: %w", name, callErr)
		}
		return providerHandle{}, fmt.Errorf("NCryptOpenStorageProvider(%s) failed with status 0x%x", name, r)
	}

	return providerHandle{handle: handle}, nil
}

func exportECCPublicBlob(keyHandle windows.Handle) ([]byte, error) {
	blobTypeW, err := windows.UTF16PtrFromString(bcryptECCPublicBlob)
	if err != nil {
		return nil, err
	}

	var size uint32
	r, _, callErr := procNCryptExportKey.Call(
		uintptr(keyHandle),
		0,
		uintptr(unsafe.Pointer(blobTypeW)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return nil, fmt.Errorf("NCryptExportKey(size) failed: %w", callErr)
		}
		return nil, fmt.Errorf("NCryptExportKey(size) failed with status 0x%x", r)
	}
	if size == 0 {
		return nil, fmt.Errorf("NCryptExportKey returned empty public key blob")
	}

	blob := make([]byte, size)
	r, _, callErr = procNCryptExportKey.Call(
		uintptr(keyHandle),
		0,
		uintptr(unsafe.Pointer(blobTypeW)),
		0,
		uintptr(unsafe.Pointer(&blob[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return nil, fmt.Errorf("NCryptExportKey failed: %w", callErr)
		}
		return nil, fmt.Errorf("NCryptExportKey failed with status 0x%x", r)
	}

	return blob[:size], nil
}

func signPayload(key verifyKey, payload []byte) ([]byte, error) {
	if key.handle == 0 {
		return nil, fmt.Errorf("verify key handle is invalid")
	}

	digest := hashPayload(payload)
	var sigSize uint32
	r, _, callErr := procNCryptSignHash.Call(
		uintptr(key.handle),
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&sigSize)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return nil, fmt.Errorf("NCryptSignHash(size) failed: %w", callErr)
		}
		return nil, fmt.Errorf("NCryptSignHash(size) failed with status 0x%x", r)
	}
	if sigSize == 0 {
		return nil, fmt.Errorf("NCryptSignHash returned empty signature")
	}

	signature := make([]byte, sigSize)
	r, _, callErr = procNCryptSignHash.Call(
		uintptr(key.handle),
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(sigSize),
		uintptr(unsafe.Pointer(&sigSize)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return nil, fmt.Errorf("NCryptSignHash failed: %w", callErr)
		}
		return nil, fmt.Errorf("NCryptSignHash failed with status 0x%x", r)
	}

	return signature[:sigSize], nil
}

func verifySignatureWithKey(key verifyKey, payload, signature []byte) error {
	if key.handle == 0 {
		return fmt.Errorf("verify key handle is invalid")
	}

	digest := hashPayload(payload)
	r, _, callErr := procNCryptVerifySignature.Call(
		uintptr(key.handle),
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(len(signature)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return fmt.Errorf("NCryptVerifySignature failed: %w", callErr)
		}
		return fmt.Errorf("NCryptVerifySignature failed with status 0x%x", r)
	}
	return nil
}

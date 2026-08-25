//go:build windows

package verify

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32dll           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = crypt32dll.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = crypt32dll.NewProc("CryptMsgClose")
	wintrustdll          = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust   = wintrustdll.NewProc("WinVerifyTrust")
)

const cmsgSignerCertInfoParam = 7

var wintrustActionGenericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

const (
	wtdUIChoiceNone             = 2
	wtdRevokeNone               = 0
	wtdRevokeWholechain         = 1
	wtdChoiceFile               = 1
	wtdStateActionIgnore        = 0
	wtdCacheOnlyURLRetrieval    = 0x00000004
	wtdProvFlagsSafer           = 0x00000100
	wtdUIContextExecute         = 0
)

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               uintptr
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

func wintrustRevocationParams(mode RevocationMode) (fdwRevocationChecks uint32, dwProvFlags uint32) {
	dwProvFlags = wtdProvFlagsSafer
	switch mode {
	case RevocationOnline:
		return wtdRevokeWholechain, dwProvFlags
	case RevocationCached:
		return wtdRevokeWholechain, dwProvFlags | wtdCacheOnlyURLRetrieval
	default:
		return wtdRevokeNone, dwProvFlags
	}
}

func verifyAuthenticodeChain(path string, mode RevocationMode) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("unable to verify authenticode signature for %s: %w", filepath.Base(path), err)
	}

	pathW, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("unable to verify authenticode signature for %s: %w", filepath.Base(path), err)
	}

	fileInfo := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: pathW,
	}

	fdw, flags := wintrustRevocationParams(mode)
	trustData := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          wtdUIChoiceNone,
		fdwRevocationChecks: fdw,
		dwUnionChoice:       wtdChoiceFile,
		pFile:               uintptr(unsafe.Pointer(&fileInfo)),
		dwStateAction:       wtdStateActionIgnore,
		dwProvFlags:         flags,
		dwUIContext:         wtdUIContextExecute,
	}

	r, _, callErr := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	if int32(r) == 0 {
		return nil
	}

	if callErr != syscall.Errno(0) && callErr != nil {
		return fmt.Errorf("authenticode signature verification failed for %s: %w", filepath.Base(path), callErr)
	}

	return fmt.Errorf("authenticode signature verification failed for %s", filepath.Base(path))
}

// SignerOrganization returns the signer organization (O=) from the embedded
// Authenticode certificate, falling back to common name when O= is absent.
func SignerOrganization(exePath string) string {
	parsed, err := signingCertificate(exePath)
	if err != nil || parsed == nil {
		return ""
	}

	if len(parsed.Subject.Organization) > 0 {
		return strings.TrimSpace(parsed.Subject.Organization[0])
	}
	if cn := strings.TrimSpace(parsed.Subject.CommonName); cn != "" {
		return cn
	}

	return ""
}

// SignerThumbprint returns the SHA-1 certificate thumbprint in uppercase hex.
func SignerThumbprint(exePath string) string {
	parsed, err := signingCertificate(exePath)
	if err != nil || parsed == nil {
		return ""
	}

	fingerprint := sha1.Sum(parsed.Raw)
	return strings.ToUpper(hex.EncodeToString(fingerprint[:]))
}

func signingCertificate(exePath string) (*x509.Certificate, error) {
	exeW, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return nil, err
	}

	var certStore, msg windows.Handle
	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(exeW),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0, nil, nil, nil,
		&certStore, &msg, nil,
	)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(certStore, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	var size uint32
	r, _, _ := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size)))
	if r == 0 || size == 0 {
		return nil, fmt.Errorf("signer certificate info unavailable")
	}

	buf := make([]byte, size)
	r, _, _ = procCryptMsgGetParam.Call(
		uintptr(msg),
		cmsgSignerCertInfoParam,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return nil, fmt.Errorf("signer certificate info unavailable")
	}

	signerCertInfo := (*windows.CertInfo)(unsafe.Pointer(&buf[0]))
	cert, _ := windows.CertFindCertificateInStore(
		certStore,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(signerCertInfo), nil,
	)
	runtime.KeepAlive(buf)
	if cert == nil {
		return nil, fmt.Errorf("signer certificate not found")
	}

	raw := make([]byte, cert.Length)
	copy(raw, unsafe.Slice(cert.EncodedCert, cert.Length))

	return x509.ParseCertificate(raw)
}

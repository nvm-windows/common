package verifycache

import (
	"path/filepath"
	"strings"
)

const (
	verifyDirName        = ".verify"
	pubKeyFileName       = "pubkey.cer"
	keyContainerFileName = "key-container.txt"
	defaultKeyName       = "AuthorSoftware.NVM.VerifyCache"
)

// Dir returns {dataRoot}/.verify.
func Dir(dataRoot string) string {
	return filepath.Join(strings.TrimSpace(dataRoot), verifyDirName)
}

// PubKeyPath returns {dataRoot}/.verify/pubkey.cer.
func PubKeyPath(dataRoot string) string {
	return filepath.Join(Dir(dataRoot), pubKeyFileName)
}

// KeyContainerPath returns {dataRoot}/.verify/key-container.txt.
func KeyContainerPath(dataRoot string) string {
	return filepath.Join(Dir(dataRoot), keyContainerFileName)
}

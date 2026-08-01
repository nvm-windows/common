package verify

import (
	"fmt"
	"path/filepath"
	"strings"
)

// VerifyNodeExecutable applies layered Authenticode verification for exePath.
//
// Step 1: WinVerifyTrust (OS chain validation).
// Step 2: AllowedSigners policy match on signer organization name (O=).
//
// Returns the matched signer organization on success.
func VerifyNodeExecutable(exePath string, allowedSigners []string) (string, error) {
	allowed := EffectiveAllowedSigners(allowedSigners)

	if err := verifyAuthenticodeChain(exePath); err != nil {
		return "", err
	}

	signer := SignerOrganization(exePath)
	if signer == "" {
		return "", fmt.Errorf("unable to verify code signer for %s", filepath.Base(exePath))
	}

	if !isAllowedSigner(signer, allowed) {
		return signer, fmt.Errorf(
			"code signer %q is not allowed (allowed signers: %s)",
			signer,
			strings.Join(allowed, ", "),
		)
	}

	return signer, nil
}

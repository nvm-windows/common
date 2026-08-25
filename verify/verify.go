package verify

import (
	"fmt"
	"path/filepath"
	"strings"

	"common/settings"
)

// Options configures layered Authenticode verification.
//
// Nil AllowedThumbprints means "read from settings"; empty non-nil means "no pin".
// Zero Revocation means seed or runtime effective mode (see Runtime).
type Options struct {
	AllowedSigners     []string
	AllowedThumbprints []string
	Revocation         RevocationMode
	// Runtime clamps online→cached. Use for shim; leave false for install/sign.
	Runtime bool
}

// VerifyNodeExecutable applies layered Authenticode verification for exePath.
//
// Step 1: WinVerifyTrust (OS chain + configured revocation).
// Step 2: AllowedSigners policy match on signer organization name (O=).
// Step 3: Optional AllowedThumbprints pin (when configured).
//
// Uses seed revocation mode (online by default; AirGapped→cached).
func VerifyNodeExecutable(exePath string, allowedSigners []string) (string, error) {
	return VerifyNodeExecutableWithOptions(exePath, Options{AllowedSigners: allowedSigners})
}

// VerifyNodeExecutableWithOptions is the explicit-options entry point.
func VerifyNodeExecutableWithOptions(exePath string, opts Options) (string, error) {
	allowed := EffectiveAllowedSigners(opts.AllowedSigners)

	mode := opts.Revocation
	if mode == "" {
		if opts.Runtime {
			mode = EffectiveRuntimeRevocationMode()
		} else {
			mode = EffectiveSeedRevocationMode()
		}
	} else if opts.Runtime {
		mode = ClampRuntimeRevocationMode(mode)
	}

	if err := verifyAuthenticodeChain(exePath, mode); err != nil {
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

	pins := opts.AllowedThumbprints
	if opts.AllowedThumbprints == nil {
		pins = settings.Global().AllowedThumbprints
	}
	if err := enforceAllowedThumbprints(exePath, pins); err != nil {
		return signer, err
	}

	return signer, nil
}

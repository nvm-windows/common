//go:build windows

package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VerifyAuthenticode validates the embedded Authenticode chain for path using
// seed revocation policy (online by default; AirGapped→cached).
func VerifyAuthenticode(path string) error {
	return verifyAuthenticodeChain(path, EffectiveSeedRevocationMode())
}

// VerifySamePublisherAs requires targetPath to pass Authenticode verification and
// match the signer organization (O=) of referencePath.
func VerifySamePublisherAs(referencePath, targetPath string) error {
	if err := verifyAuthenticodeChain(targetPath, EffectiveSeedRevocationMode()); err != nil {
		return err
	}

	referencePath = strings.TrimSpace(referencePath)
	if referencePath == "" {
		return fmt.Errorf("reference executable path is empty")
	}

	refOrg := SignerOrganization(referencePath)
	if refOrg == "" {
		refThumb := SignerThumbprint(referencePath)
		if refThumb == "" {
			return fmt.Errorf("unable to resolve signer for %s", filepath.Base(referencePath))
		}
		tgtThumb := SignerThumbprint(targetPath)
		if tgtThumb == "" || !strings.EqualFold(refThumb, tgtThumb) {
			return fmt.Errorf("%s is not signed by the same publisher as %s", filepath.Base(targetPath), filepath.Base(referencePath))
		}
		return nil
	}

	tgtOrg := SignerOrganization(targetPath)
	if tgtOrg == "" {
		return fmt.Errorf("unable to resolve signer for %s", filepath.Base(targetPath))
	}
	if !strings.EqualFold(refOrg, tgtOrg) {
		return fmt.Errorf(
			"%s signer %q does not match %s signer %q",
			filepath.Base(targetPath),
			tgtOrg,
			filepath.Base(referencePath),
			refOrg,
		)
	}

	return nil
}

// VerifySamePublisherAsExecutable is a convenience wrapper using os.Executable().
func VerifySamePublisherAsExecutable(targetPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("unable to resolve sync executable path: %w", err)
	}
	return VerifySamePublisherAs(exePath, targetPath)
}

//go:build windows

package fs

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	aceInherit = windows.CONTAINER_INHERIT_ACE | windows.OBJECT_INHERIT_ACE

	dirReadExecute = windows.GENERIC_READ | windows.GENERIC_EXECUTE

	// Write-capable bits only. Do not include READ_CONTROL/SYNCHRONIZE — those
	// overlap FILE_GENERIC_READ/EXECUTE and false-positive AuthUsers RX ACEs.
	// FILE_DELETE_CHILD = 0x40 (not always named in x/sys).
	crossUserWriteMask = windows.FILE_WRITE_DATA |
		windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_EA |
		windows.FILE_WRITE_ATTRIBUTES |
		windows.ACCESS_MASK(0x00000040) |
		windows.DELETE |
		windows.WRITE_DAC |
		windows.WRITE_OWNER |
		windows.GENERIC_WRITE |
		windows.GENERIC_ALL
)

var runtimeDataDirNames = []string{".shim", ".link", ".sync", ".cache", ".nodejs", ".verify"}

// IsRiskyManagedPath reports whether a directory should receive an explicit
// restrictive DACL to prevent cross-user executable planting.
func IsRiskyManagedPath(path string) bool {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return false
	}
	if isUnderSafeManagedRoot(path) {
		return false
	}
	if isDriveRootChild(path) {
		return true
	}
	parent := filepath.Dir(path)
	if parent != path && isDriveRootChild(parent) {
		return true
	}
	return daclAllowsCrossPrincipalWrite(path)
}

// HasRiskyDataRootLayout reports when runtime data directories would live on a drive root.
func HasRiskyDataRootLayout(installRoot string) bool {
	installRoot = filepath.Clean(installRoot)
	if installRoot == "" || installRoot == "." {
		return false
	}
	return isDriveRoot(filepath.Dir(installRoot))
}

// WarnRiskyRootLayout prints guidance when InstallRoot leaves data on a drive root.
func WarnRiskyRootLayout(installRoot string) {
	if !HasRiskyDataRootLayout(installRoot) {
		return
	}
	parent := filepath.Dir(filepath.Clean(installRoot))
	fmt.Fprintf(
		os.Stderr,
		"warning: install root %q places NVM runtime data on drive root %q. Prefer a nested path such as %s\\installs.\n",
		installRoot,
		parent,
		parent,
	)
}

// HardenManagedDirectory applies a protected DACL on risky managed directories.
// Fail-closed: errors are returned so callers can abort install/bootstrap.
func HardenManagedDirectory(path string) error {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil
	}
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("unable to inspect %s for ACL hardening: %w", path, err)
	}
	if !IsRiskyManagedPath(path) {
		return nil
	}
	if err := applyHardenedDACL(path); err != nil {
		log.Printf("nvm: could not harden directory ACL for %s: %v", path, err)
		return fmt.Errorf("ACL hardening failed for %s: %w", path, err)
	}
	if err := verifyHardenedDACL(path); err != nil {
		return fmt.Errorf("ACL hardening verification failed for %s: %w", path, err)
	}
	return nil
}

// HardenRuntimeLayout hardens the install root, data root, and known runtime dirs.
// Returns the first hardening failure (fail-closed for SEC-06).
func HardenRuntimeLayout(installRoot, dataRoot string) error {
	var first error
	harden := func(path string) {
		if err := HardenManagedDirectory(path); err != nil && first == nil {
			first = err
		}
	}
	harden(dataRoot)
	harden(installRoot)
	for _, name := range runtimeDataDirNames {
		harden(filepath.Join(dataRoot, name))
	}
	for _, sub := range []string{"versions", "http"} {
		harden(filepath.Join(dataRoot, ".cache", sub))
	}
	return first
}

// RepairRuntimeACLs re-applies managed DACLs and re-locks .shim / proxy.exe.
// Intended for elevated `nvm doctor --autofix` when unlock windows fail.
func RepairRuntimeACLs(installRoot, dataRoot string) error {
	installRoot = filepath.Clean(strings.TrimSpace(installRoot))
	dataRoot = filepath.Clean(strings.TrimSpace(dataRoot))
	if installRoot == "" || dataRoot == "" {
		return fmt.Errorf("install root and data root are required for ACL repair")
	}
	if err := HardenRuntimeLayout(installRoot, dataRoot); err != nil {
		return err
	}
	shimDir := filepath.Join(dataRoot, ".shim")
	if err := LockShimDirectory(shimDir); err != nil {
		return fmt.Errorf("failed to lock shim directory: %w", err)
	}
	proxyPath := filepath.Join(dataRoot, "proxy.exe")
	if err := LockProxyExecutable(proxyPath); err != nil {
		return fmt.Errorf("failed to lock proxy executable: %w", err)
	}
	if err := HardenVerifyDirectory(filepath.Join(dataRoot, ".verify")); err != nil {
		return fmt.Errorf("failed to harden verify directory: %w", err)
	}
	return nil
}

// HardenVerifyDirectory always applies a protected DACL on .verify (DI-01 D),
// even under LocalAppData where HardenManagedDirectory would otherwise no-op.
func HardenVerifyDirectory(path string) error {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil
	}
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("unable to inspect %s for verify ACL hardening: %w", path, err)
	}
	if err := applyHardenedDACL(path); err != nil {
		log.Printf("nvm: could not harden verify directory ACL for %s: %v", path, err)
		return fmt.Errorf("verify ACL hardening failed for %s: %w", path, err)
	}
	if err := verifyHardenedDACL(path); err != nil {
		return fmt.Errorf("verify ACL hardening verification failed for %s: %w", path, err)
	}
	return nil
}

func verifyHardenedDACL(path string) error {
	if daclAllowsCrossPrincipalWrite(path) {
		return fmt.Errorf("directory remains writable by Authenticated Users or Users")
	}
	return nil
}

func isUnderSafeManagedRoot(path string) bool {
	path = filepath.Clean(path)
	lowerPath := strings.ToLower(path)
	for _, root := range safeManagedRoots() {
		root = filepath.Clean(root)
		if root == "" {
			continue
		}
		lowerRoot := strings.ToLower(root)
		if lowerPath == lowerRoot || strings.HasPrefix(lowerPath, lowerRoot+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func safeManagedRoots() []string {
	// ProgramData intentionally omitted: it is often Users-writable (CREATOR OWNER)
	// and was the v1 shared-plant EoP surface. Soft ProgramData roots are hardened
	// via daclAllowsCrossPrincipalWrite instead of being skipped as "safe".
	return []string{
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("USERPROFILE"),
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
	}
}

func isDriveRoot(path string) bool {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if volume == "" {
		return false
	}
	rest := strings.TrimPrefix(path, volume)
	rest = strings.Trim(rest, `\`)
	return rest == ""
}

func isDriveRootChild(path string) bool {
	return pathDepthFromVolume(path) == 1
}

func pathDepthFromVolume(path string) int {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if volume == "" {
		return -1
	}
	rest := strings.TrimPrefix(path, volume)
	rest = strings.Trim(rest, `\`)
	if rest == "" {
		return 0
	}
	return len(strings.Split(rest, `\`))
}

func daclAllowsCrossPrincipalWrite(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}

	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}

	authUsers, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		return false
	}

	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return false
	}

	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			continue
		}
		if ace == nil {
			continue
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !windows.EqualSid(sid, authUsers) && !windows.EqualSid(sid, users) {
			continue
		}
		if ace.Mask&crossUserWriteMask != 0 {
			return true
		}
	}

	return false
}

func applyHardenedDACL(path string) error {
	entries, release, err := hardenedExplicitAccess()
	if err != nil {
		return err
	}
	defer release()

	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

func hardenedExplicitAccess() ([]windows.EXPLICIT_ACCESS, func(), error) {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, err
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, nil, err
	}
	authUsersSID, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		return nil, nil, err
	}
	creatorOwnerSID, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		return nil, nil, err
	}

	release := func() {
		// SID pointers are referenced by ACL construction; do not free here.
	}

	entries := []windows.EXPLICIT_ACCESS{
		explicitAccess(systemSID, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		explicitAccess(adminSID, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		explicitAccess(authUsersSID, dirReadExecute, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		explicitAccess(creatorOwnerSID, windows.GENERIC_ALL, windows.TRUSTEE_IS_USER),
	}

	return entries, release, nil
}

func explicitAccess(sid *windows.SID, access windows.ACCESS_MASK, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       aceInherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

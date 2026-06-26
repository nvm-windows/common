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

	crossUserWriteMask = windows.FILE_GENERIC_WRITE |
		windows.GENERIC_WRITE |
		windows.GENERIC_ALL |
		windows.DELETE |
		windows.WRITE_DAC |
		windows.WRITE_OWNER
)

var runtimeDataDirNames = []string{".shim", ".link", ".sync", ".cache", ".nodejs"}

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
// Errors are logged and returned; callers should treat hardening as best-effort.
func HardenManagedDirectory(path string) error {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil
	}
	if !IsRiskyManagedPath(path) {
		return nil
	}
	if err := applyHardenedDACL(path); err != nil {
		log.Printf("nvm: warning: could not harden directory ACL for %s: %v", path, err)
		return err
	}
	return nil
}

// HardenRuntimeLayout hardens the install root, data root, and known runtime dirs.
func HardenRuntimeLayout(installRoot, dataRoot string) {
	_ = HardenManagedDirectory(dataRoot)
	_ = HardenManagedDirectory(installRoot)
	for _, name := range runtimeDataDirNames {
		_ = HardenManagedDirectory(filepath.Join(dataRoot, name))
	}
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
	return []string{
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("USERPROFILE"),
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("ProgramData"),
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
	defer windows.FreeSid(authUsers)

	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(users)

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
		windows.FreeSid(systemSID)
		windows.FreeSid(adminSID)
		windows.FreeSid(authUsersSID)
		windows.FreeSid(creatorOwnerSID)
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

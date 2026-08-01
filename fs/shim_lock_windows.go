//go:build windows

package fs

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const (
	shimDirWriteWindow = windows.ACCESS_MASK(0x00000002|0x00000004|0x00000040) | // FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD
		windows.DELETE |
		windows.WRITE_DAC |
		windows.FILE_WRITE_DATA |
		windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_ATTRIBUTES |
		windows.FILE_WRITE_EA

	proxyFileReadExecute = windows.FILE_READ_DATA |
		windows.FILE_READ_ATTRIBUTES |
		windows.FILE_READ_EA |
		windows.FILE_EXECUTE |
		windows.SYNCHRONIZE |
		windows.READ_CONTROL

	proxyFileWriteWindow = windows.FILE_WRITE_DATA |
		windows.FILE_APPEND_DATA |
		windows.DELETE |
		windows.WRITE_DAC |
		windows.FILE_WRITE_ATTRIBUTES |
		windows.FILE_WRITE_EA
)

// LockShimDirectory applies a read-only DACL on .shim for the current user.
func LockShimDirectory(path string) error {
	return applyShimDirectoryDACL(path, false)
}

// UnlockShimDirectory grants the current user a short-lived write window on .shim.
func UnlockShimDirectory(path string) error {
	return applyShimDirectoryDACL(path, true)
}

// LockProxyExecutable applies a read-only DACL on the shared proxy shim.
func LockProxyExecutable(path string) error {
	return applyProxyExecutableDACL(path, false)
}

// UnlockProxyExecutable grants the current user a short-lived write window on proxy.exe.
func UnlockProxyExecutable(path string) error {
	return applyProxyExecutableDACL(path, true)
}

// RunWithRuntimeShimWrite unlocks .shim (and proxy.exe when present), runs fn, then re-locks.
func RunWithRuntimeShimWrite(shimDir, proxyPath string, fn func() error) error {
	shimDir = filepath.Clean(shimDir)
	if shimDir == "" || shimDir == "." {
		return fmt.Errorf("shim directory path is empty")
	}

	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return fmt.Errorf("failed to create shim directory: %w", err)
	}

	if err := UnlockShimDirectory(shimDir); err != nil {
		return err
	}

	proxyUnlocked := false
	if proxyPath = filepath.Clean(proxyPath); proxyPath != "" && proxyPath != "." {
		if err := UnlockProxyExecutable(proxyPath); err != nil {
			_ = LockShimDirectory(shimDir)
			return err
		}
		proxyUnlocked = true
	}

	var fnErr error
	defer func() {
		if proxyUnlocked {
			if lockErr := LockProxyExecutable(proxyPath); lockErr != nil && fnErr == nil {
				fnErr = lockErr
			}
		}
		if lockErr := LockShimDirectory(shimDir); lockErr != nil && fnErr == nil {
			fnErr = lockErr
		}
	}()

	fnErr = fn()
	return fnErr
}

func applyShimDirectoryDACL(path string, writeWindow bool) error {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return fmt.Errorf("shim directory path is empty")
	}

	entries, release, err := shimDirectoryExplicitAccess(writeWindow)
	if err != nil {
		return err
	}
	defer release()

	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}

	return setProtectedObjectDACL(path, dacl)
}

func applyProxyExecutableDACL(path string, writeWindow bool) error {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return fmt.Errorf("proxy executable path is empty")
	}

	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to inspect proxy executable %s: %w", path, err)
	}

	entries, release, err := proxyExecutableExplicitAccess(writeWindow)
	if err != nil {
		return err
	}
	defer release()

	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}

	return setProtectedObjectDACL(path, dacl)
}

func setProtectedObjectDACL(path string, dacl *windows.ACL) error {
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

func shimDirectoryExplicitAccess(writeWindow bool) ([]windows.EXPLICIT_ACCESS, func(), error) {
	entries, release, err := hardenedExplicitAccess()
	if err != nil {
		return nil, nil, err
	}

	if writeWindow {
		entries[len(entries)-1].AccessPermissions |= shimDirWriteWindow
	} else {
		entries[len(entries)-1].AccessPermissions = windows.ACCESS_MASK(dirReadExecute | windows.WRITE_DAC)
	}

	return entries, release, nil
}

func proxyExecutableExplicitAccess(writeWindow bool) ([]windows.EXPLICIT_ACCESS, func(), error) {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, err
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		windows.FreeSid(systemSID)
		return nil, nil, err
	}
	authUsersSID, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		windows.FreeSid(systemSID)
		windows.FreeSid(adminSID)
		return nil, nil, err
	}
	creatorOwnerSID, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		windows.FreeSid(systemSID)
		windows.FreeSid(adminSID)
		windows.FreeSid(authUsersSID)
		return nil, nil, err
	}

	release := func() {
		// SID pointers are referenced by ACL construction; do not free here.
	}

	ownerAccess := windows.ACCESS_MASK(proxyFileReadExecute | windows.WRITE_DAC)
	if writeWindow {
		ownerAccess |= proxyFileWriteWindow
	}

	entries := []windows.EXPLICIT_ACCESS{
		explicitAccess(systemSID, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		explicitAccess(adminSID, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		explicitAccess(authUsersSID, proxyFileReadExecute, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		explicitAccess(creatorOwnerSID, ownerAccess, windows.TRUSTEE_IS_USER),
	}

	return entries, release, nil
}

//go:build windows

package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// AllowsCrossUserWrite reports whether Users/Authenticated Users can write the path.
func AllowsCrossUserWrite(path string) bool {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return false
	}
	if _, err := os.Lstat(path); err != nil {
		return false
	}
	return daclAllowsCrossPrincipalWrite(path)
}

// WarnSharedWritableRoot warns when an install root is writable by other users.
func WarnSharedWritableRoot(installRoot string) {
	installRoot = filepath.Clean(installRoot)
	if installRoot == "" || installRoot == "." {
		return
	}
	if !AllowsCrossUserWrite(installRoot) {
		return
	}
	fmt.Fprintf(
		os.Stderr,
		"warning: install root %q is writable by other users. Prefer %%LOCALAPPDATA%%\\Author Software\\nvm\\installs (or a private Program Files path). Shared writable roots enable version-dir planting.\n",
		installRoot,
	)
}

// IsReparsePoint reports whether path is a symlink/junction/mount-point.
func IsReparsePoint(path string) (bool, error) {
	path = filepath.Clean(path)
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return false, err
	}
	return attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

// CheckVersionDirTrust refuses planted/hijackable version directories.
// Missing path is OK. Existing reparse or cross-user-writable dirs are rejected.
func CheckVersionDirTrust(path string) error {
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("version path is not a directory: %s", path)
	}
	reparse, err := IsReparsePoint(path)
	if err != nil {
		return err
	}
	if reparse {
		return fmt.Errorf("refusing version directory %s: path is a reparse point (symlink/junction)", path)
	}
	if AllowsCrossUserWrite(path) {
		return fmt.Errorf("refusing version directory %s: writable by other users (possible plant)", path)
	}
	return nil
}

// AssertNoReparseBetween rejects writing through junctions between root and target (inclusive).
func AssertNoReparseBetween(root, target string) error {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	if root == "" || target == "" {
		return nil
	}

	cur := target
	for {
		if _, err := os.Lstat(cur); err == nil {
			reparse, err := IsReparsePoint(cur)
			if err != nil {
				return err
			}
			if reparse {
				return fmt.Errorf("refusing path %s: reparse point at %s", target, cur)
			}
		} else if !os.IsNotExist(err) {
			return err
		}

		if equalFoldPath(cur, root) {
			return nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
}

// FinalizeVersionDirectoryACL applies post-install ACL policy for a version directory.
// Version trees are not runtime shim surfaces: they should inherit admin-curated parent
// ACLs (#1266) instead of receiving protected runtime DACLs (SEC-06).
func FinalizeVersionDirectoryACL(installDir string) error {
	installDir = filepath.Clean(installDir)
	if installDir == "" || installDir == "." {
		return nil
	}
	if err := CheckVersionDirTrust(installDir); err != nil {
		return err
	}
	if isUnderSafeManagedRoot(installDir) {
		return nil
	}

	parent := filepath.Dir(installDir)
	if AllowsCrossUserWrite(parent) {
		return fmt.Errorf(
			"refusing version directory %s: install root parent %q is writable by other users",
			installDir,
			parent,
		)
	}

	EnableInheritance(installDir)
	return CheckVersionDirTrust(installDir)
}

func equalFoldPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

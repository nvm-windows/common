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
// Version trees prefer inheriting a hardened install-root DACL (#1266). When inheritance
// still leaves cross-user write (common on custom roots under C:\…), fall back to a
// protected managed DACL so proxy NVM4305 checks pass.
func FinalizeVersionDirectoryACL(installDir string) error {
	installDir = filepath.Clean(installDir)
	if installDir == "" || installDir == "." {
		return nil
	}
	if _, err := os.Lstat(installDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	reparse, err := IsReparsePoint(installDir)
	if err != nil {
		return err
	}
	if reparse {
		return fmt.Errorf("refusing version directory %s: path is a reparse point (symlink/junction)", installDir)
	}

	if isUnderSafeManagedRoot(installDir) {
		return CheckVersionDirTrust(installDir)
	}

	parent := filepath.Dir(installDir)
	if err := HardenManagedDirectory(parent); err != nil {
		return err
	}
	if AllowsCrossUserWrite(parent) {
		return fmt.Errorf(
			"refusing version directory %s: install root parent %q is writable by other users",
			installDir,
			parent,
		)
	}

	EnableInheritance(installDir)
	if err := CheckVersionDirTrust(installDir); err == nil {
		return nil
	}

	if err := HardenManagedDirectory(installDir); err != nil {
		return err
	}
	return CheckVersionDirTrust(installDir)
}

// ListInstalledVersionDirs returns version directories under installRoot that contain node.exe.
func ListInstalledVersionDirs(installRoot string) ([]string, error) {
	installRoot = filepath.Clean(strings.TrimSpace(installRoot))
	if installRoot == "" || installRoot == "." {
		return nil, nil
	}

	entries, err := os.ReadDir(installRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	out := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) == 0 || (name[0] != 'v' && name[0] != 'V') {
			continue
		}
		dir := filepath.Join(installRoot, name)
		if _, err := os.Stat(filepath.Join(dir, "node.exe")); err != nil {
			continue
		}
		out = append(out, dir)
	}
	return out, nil
}

// VersionDirectoryTrustIssue describes a version dir that fails proxy trust checks.
type VersionDirectoryTrustIssue struct {
	Path   string
	Reason string
}

// CollectVersionDirectoryTrustIssues lists installed version dirs that fail CheckVersionDirTrust.
func CollectVersionDirectoryTrustIssues(installRoot string) ([]VersionDirectoryTrustIssue, error) {
	dirs, err := ListInstalledVersionDirs(installRoot)
	if err != nil {
		return nil, err
	}
	issues := make([]VersionDirectoryTrustIssue, 0)
	for _, dir := range dirs {
		if err := CheckVersionDirTrust(dir); err != nil {
			issues = append(issues, VersionDirectoryTrustIssue{
				Path:   dir,
				Reason: err.Error(),
			})
		}
	}
	return issues, nil
}

// RepairVersionDirectoryTrust hardens the install root, then repairs each installed
// version directory so proxy NVM4305 checks pass.
func RepairVersionDirectoryTrust(installRoot string) (repaired int, remaining []VersionDirectoryTrustIssue, err error) {
	installRoot = filepath.Clean(strings.TrimSpace(installRoot))
	if installRoot == "" || installRoot == "." {
		return 0, nil, nil
	}

	if err := HardenManagedDirectory(installRoot); err != nil {
		return 0, nil, err
	}

	dirs, err := ListInstalledVersionDirs(installRoot)
	if err != nil {
		return 0, nil, err
	}

	for _, dir := range dirs {
		before := CheckVersionDirTrust(dir)
		if before == nil {
			continue
		}
		if ferr := FinalizeVersionDirectoryACL(dir); ferr != nil {
			remaining = append(remaining, VersionDirectoryTrustIssue{
				Path:   dir,
				Reason: ferr.Error(),
			})
			continue
		}
		if CheckVersionDirTrust(dir) == nil {
			repaired++
		} else {
			remaining = append(remaining, VersionDirectoryTrustIssue{
				Path:   dir,
				Reason: before.Error(),
			})
		}
	}
	return repaired, remaining, nil
}

func equalFoldPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

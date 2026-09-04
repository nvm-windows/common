//go:build !windows

package fs

// AllowsCrossUserWrite is a no-op off Windows.
func AllowsCrossUserWrite(path string) bool { return false }

// WarnSharedWritableRoot is a no-op off Windows.
func WarnSharedWritableRoot(installRoot string) {}

// IsReparsePoint is a no-op off Windows.
func IsReparsePoint(path string) (bool, error) { return false, nil }

// CheckVersionDirTrust is a no-op off Windows.
func CheckVersionDirTrust(path string) error { return nil }

// FinalizeVersionDirectoryACL is a no-op off Windows.
func FinalizeVersionDirectoryACL(installDir string) error { return nil }

// ListInstalledVersionDirs is a no-op off Windows.
func ListInstalledVersionDirs(installRoot string) ([]string, error) { return nil, nil }

// VersionDirectoryTrustIssue describes a version dir that fails proxy trust checks.
type VersionDirectoryTrustIssue struct {
	Path   string
	Reason string
}

// CollectVersionDirectoryTrustIssues is a no-op off Windows.
func CollectVersionDirectoryTrustIssues(installRoot string) ([]VersionDirectoryTrustIssue, error) {
	return nil, nil
}

// RepairVersionDirectoryTrust is a no-op off Windows.
func RepairVersionDirectoryTrust(installRoot string) (repaired int, remaining []VersionDirectoryTrustIssue, err error) {
	return 0, nil, nil
}

// AssertNoReparseBetween is a no-op off Windows.
func AssertNoReparseBetween(root, target string) error { return nil }

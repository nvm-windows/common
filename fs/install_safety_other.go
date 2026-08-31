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

// AssertNoReparseBetween is a no-op off Windows.
func AssertNoReparseBetween(root, target string) error { return nil }

//go:build !windows

package fs

import "strings"

// CheckInstallRootAllowed is a no-op off Windows.
func CheckInstallRootAllowed(path string) error { return nil }

// IsSafeToDeleteInstallRoot reports whether uninstall may DelTree the storage path.
func IsSafeToDeleteInstallRoot(path string) bool {
	return strings.TrimSpace(path) != ""
}

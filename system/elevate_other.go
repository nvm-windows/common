//go:build !windows

package system

import "fmt"

// IsElevated is a no-op off Windows.
func IsElevated() (bool, error) { return false, nil }

// RelaunchElevated is unsupported off Windows.
func RelaunchElevated(args []string) (exitCode int, err error) {
	return 1, fmt.Errorf("elevation is only supported on Windows")
}

// RunElevated is unsupported off Windows.
func RunElevated(exe string, args []string) (exitCode int, err error) {
	return 1, fmt.Errorf("elevation is only supported on Windows")
}

//go:build !windows

package fs

import "fmt"

func IsRiskyManagedPath(path string) bool { return false }

func HasRiskyDataRootLayout(installRoot string) bool { return false }

func WarnRiskyRootLayout(installRoot string) {}

func HardenManagedDirectory(path string) error { return nil }

func HardenRuntimeLayout(installRoot, dataRoot string) error { return nil }

func HardenVerifyDirectory(path string) error { return nil }

func RepairRuntimeACLs(installRoot, dataRoot string) error {
	return fmt.Errorf("ACL repair is only supported on Windows")
}

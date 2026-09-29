//go:build !windows

package system

import "runtime"

func BuildArchitecture() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

func NativeArchitecture() (string, bool) { return BuildArchitecture(), true }

func ArchitectureMismatch() (bool, string, string) {
	a := BuildArchitecture()
	return false, a, a
}

//go:build windows

package system

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	imageFileMachineAMD64 = 0x8664
	imageFileMachineARM64 = 0xaa64
)

var isWow64Process2 = kernel32.NewProc("IsWow64Process2")

// BuildArchitecture is the architecture this binary was compiled for.
func BuildArchitecture() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

// NativeArchitecture returns host OS arch (amd64|arm64) via IsWow64Process2.
// Under Prism, GOARCH can be amd64 while native is arm64.
// If API unavailable or unrecognized machine, returns BuildArchitecture() and ok=false.
func NativeArchitecture() (arch string, ok bool) {
	var processMachine, nativeMachine uint16
	r1, _, callErr := isWow64Process2.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&processMachine)),
		uintptr(unsafe.Pointer(&nativeMachine)),
	)
	if r1 == 0 {
		_ = callErr
		return BuildArchitecture(), false
	}
	switch nativeMachine {
	case imageFileMachineAMD64:
		return "amd64", true
	case imageFileMachineARM64:
		return "arm64", true
	default:
		return BuildArchitecture(), false
	}
}

// ArchitectureMismatch reports whether build arch differs from native OS arch.
func ArchitectureMismatch() (mismatch bool, buildArch, nativeArch string) {
	buildArch = BuildArchitecture()
	nativeArch, ok := NativeArchitecture()
	if !ok {
		return false, buildArch, nativeArch
	}
	return buildArch != nativeArch, buildArch, nativeArch
}

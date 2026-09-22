//go:build windows

package system

import "testing"

func TestArchitectureMismatchWhenNativeMatchesBuild(t *testing.T) {
	mismatch, buildArch, nativeArch := ArchitectureMismatch()
	if buildArch != BuildArchitecture() {
		t.Fatalf("buildArch=%q want %q", buildArch, BuildArchitecture())
	}
	native, ok := NativeArchitecture()
	if ok && buildArch == native && mismatch {
		t.Fatalf("mismatch=true when build=%q native=%q", buildArch, nativeArch)
	}
}

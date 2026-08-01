//go:build windows

package fs

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// ReplaceExecutable atomically replaces target with replacement.
func ReplaceExecutable(replacement, target string) error {
	replPtr, err := windows.UTF16PtrFromString(replacement)
	if err != nil {
		return fmt.Errorf("replacement path: %w", err)
	}
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("target path: %w", err)
	}

	const flags = windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH
	if err := windows.MoveFileEx(replPtr, targetPtr, flags); err != nil {
		return fmt.Errorf("MoveFileEx replace: %w", err)
	}
	return nil
}

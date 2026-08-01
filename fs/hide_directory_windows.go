//go:build windows

package fs

import (
	"os"
	"path/filepath"
	"syscall"
)

// RuntimeDataDirNames lists dot-prefixed runtime directories under the NVM data root.
func RuntimeDataDirNames() []string {
	return append([]string(nil), runtimeDataDirNames...)
}

// HideDirectory sets the hidden (+ directory) file attributes on path when it exists.
func HideDirectory(path string) error {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil
	}

	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	if err := syscall.SetFileAttributes(ptr, syscall.FILE_ATTRIBUTE_HIDDEN|syscall.FILE_ATTRIBUTE_DIRECTORY); err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_ACCESS_DENIED {
			if _, statErr := os.Lstat(path); statErr == nil {
				return nil
			}
		}
		return err
	}

	return nil
}

// EnsureHiddenDirectory creates path when needed and marks it hidden.
func EnsureHiddenDirectory(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}

	_ = HardenManagedDirectory(path)
	return HideDirectory(path)
}

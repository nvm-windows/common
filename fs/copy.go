package fs

import (
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		os.Remove(dst)
		return err
	}
	return cerr
}

// SetHidden marks a directory as hidden using the Windows file attribute.
// Errors are intentionally ignored — hiding is best-effort.
func SetHidden(path string) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err == nil {
		syscall.SetFileAttributes(ptr, syscall.FILE_ATTRIBUTE_HIDDEN|syscall.FILE_ATTRIBUTE_DIRECTORY)
	}
}

// ClearHidden removes the hidden attribute from a directory.
func ClearHidden(path string) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err == nil {
		syscall.SetFileAttributes(ptr, syscall.FILE_ATTRIBUTE_DIRECTORY)
	}
}

// EnableInheritance re-enables ACL inheritance on dir and all its contents,
// equivalent to: icacls dir /inheritance:e /T
func EnableInheritance(dir string) {
	filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// UNPROTECTED_DACL_SECURITY_INFORMATION clears the "protected" (no-inherit) flag
		windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, nil, nil)
		return nil
	})
}

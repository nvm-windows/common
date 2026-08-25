//go:build windows

package verifycache

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	winreg "golang.org/x/sys/windows/registry"
)

type fileSecurityState struct {
	VolumeSerial uint32
	FileID       uint64
	USN          uint64
}

func nodeFileTimes(path string) (size int64, mtime uint64, err error) {
	pathW, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}

	var info windows.Win32FileAttributeData
	if err := windows.GetFileAttributesEx(pathW, windows.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&info))); err != nil {
		return 0, 0, err
	}

	size = int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	mtime = uint64(info.LastWriteTime.HighDateTime)<<32 | uint64(info.LastWriteTime.LowDateTime)
	return size, mtime, nil
}

func nodeFileSecurityState(path string) (fileSecurityState, error) {
	pathW, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fileSecurityState{}, err
	}
	handle, err := windows.CreateFile(
		pathW,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fileSecurityState{}, err
	}
	defer windows.CloseHandle(handle)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fileSecurityState{}, err
	}

	var output [512]uint64
	outputBytes := unsafe.Slice((*byte)(unsafe.Pointer(&output[0])), int(unsafe.Sizeof(output)))
	var returned uint32
	input := [2]uint16{2, 2}
	if err := windows.DeviceIoControl(
		handle,
		windows.FSCTL_READ_FILE_USN_DATA,
		(*byte)(unsafe.Pointer(&input[0])),
		uint32(unsafe.Sizeof(input)),
		&outputBytes[0],
		uint32(len(outputBytes)),
		&returned,
		nil,
	); err != nil {
		return fileSecurityState{}, err
	}
	if returned < 32 || binary.LittleEndian.Uint16(outputBytes[4:6]) != 2 {
		return fileSecurityState{}, fmt.Errorf("unsupported USN record")
	}

	return fileSecurityState{
		VolumeSerial: info.VolumeSerialNumber,
		FileID:       binary.LittleEndian.Uint64(outputBytes[8:16]),
		USN:          binary.LittleEndian.Uint64(outputBytes[24:32]),
	}, nil
}

func deleteRegistrySubKey(registryPath string) error {
	root, remainder, err := parseRegistryPath(registryPath)
	if err != nil {
		return err
	}
	if remainder == "" {
		return nil
	}

	lastSlash := strings.LastIndex(remainder, `\`)
	if lastSlash == -1 {
		return fmt.Errorf("registry path %q has no subkey to delete", registryPath)
	}

	parentPath := remainder[:lastSlash]
	subKey := remainder[lastSlash+1:]

	parent, err := winreg.OpenKey(root, parentPath, winreg.SET_VALUE)
	if err != nil {
		if err == winreg.ErrNotExist {
			return nil
		}
		return err
	}
	defer parent.Close()

	if err := winreg.DeleteKey(parent, subKey); err != nil {
		if err == winreg.ErrNotExist {
			return nil
		}
		return err
	}
	return nil
}

func parseRegistryPath(source string) (winreg.Key, string, error) {
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return 0, "", fmt.Errorf("registry path is required")
	}

	normalized := strings.ReplaceAll(trimmed, "/", `\`)
	parts := strings.SplitN(normalized, `\`, 2)
	rootLabel := strings.TrimSuffix(strings.ToUpper(strings.TrimSpace(parts[0])), ":")

	roots := map[string]winreg.Key{
		"HKEY_LOCAL_MACHINE": winreg.LOCAL_MACHINE,
		"HKLM":               winreg.LOCAL_MACHINE,
		"HKEY_CURRENT_USER":  winreg.CURRENT_USER,
		"HKCU":               winreg.CURRENT_USER,
	}

	root, ok := roots[rootLabel]
	if !ok {
		return 0, "", fmt.Errorf("unsupported registry root %q", rootLabel)
	}

	if len(parts) == 1 {
		return root, "", nil
	}

	return root, strings.TrimLeft(strings.TrimSpace(parts[1]), `\`), nil
}

func verifyCacheSignature(publicKeyBlob, payload, signature []byte) error {
	return verifyECDSA(publicKeyBlob, hashPayload(payload), signature)
}

func verifyECDSA(publicKeyBlob []byte, digest [32]byte, signature []byte) error {
	var algHandle windows.Handle
	algName, err := windows.UTF16PtrFromString(bcryptECDSA_P256)
	if err != nil {
		return err
	}

	r, _, callErr := procBCryptOpenAlgorithmProvider.Call(
		uintptr(unsafe.Pointer(&algHandle)),
		uintptr(unsafe.Pointer(algName)),
		uintptr(unsafe.Pointer(msPrimitiveProviderW)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return fmt.Errorf("BCryptOpenAlgorithmProvider failed: %w", callErr)
		}
		return fmt.Errorf("BCryptOpenAlgorithmProvider failed with status 0x%x", r)
	}
	defer procBCryptCloseAlgorithmProvider.Call(uintptr(algHandle), 0)

	var keyHandle windows.Handle
	blobTypeW, err := windows.UTF16PtrFromString(bcryptECCPublicBlob)
	if err != nil {
		return err
	}

	r, _, callErr = procBCryptImportKeyPair.Call(
		uintptr(algHandle),
		0,
		uintptr(unsafe.Pointer(blobTypeW)),
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(&publicKeyBlob[0])),
		uintptr(len(publicKeyBlob)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return fmt.Errorf("BCryptImportKeyPair failed: %w", callErr)
		}
		return fmt.Errorf("BCryptImportKeyPair failed with status 0x%x", r)
	}
	defer procBCryptDestroyKey.Call(uintptr(keyHandle))

	r, _, callErr = procBCryptVerifySignature.Call(
		uintptr(keyHandle),
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(len(signature)),
		0,
	)
	if r != 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return fmt.Errorf("BCryptVerifySignature failed: %w", callErr)
		}
		return fmt.Errorf("BCryptVerifySignature failed with status 0x%x", r)
	}

	return nil
}

var (
	bcrypt                           = windows.NewLazySystemDLL("bcrypt.dll")
	procBCryptOpenAlgorithmProvider  = bcrypt.NewProc("BCryptOpenAlgorithmProvider")
	procBCryptCloseAlgorithmProvider = bcrypt.NewProc("BCryptCloseAlgorithmProvider")
	procBCryptImportKeyPair          = bcrypt.NewProc("BCryptImportKeyPair")
	procBCryptDestroyKey             = bcrypt.NewProc("BCryptDestroyKey")
	procBCryptVerifySignature        = bcrypt.NewProc("BCryptVerifySignature")
	msPrimitiveProviderW             = windows.StringToUTF16Ptr(msPrimitiveProvider)
)

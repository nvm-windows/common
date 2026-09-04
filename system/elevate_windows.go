//go:build windows

package system

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	seeMaskNoCloseProcess = 0x00000040
	swHide                = 0
)

type shellExecuteInfoW struct {
	CbSize       uint32
	FMask        uint32
	Hwnd         windows.Handle
	LpVerb       *uint16
	LpFile       *uint16
	LpParameters *uint16
	LpDirectory  *uint16
	NShow        int32
	HInstApp     windows.Handle
	LpIDList     uintptr
	LpClass      *uint16
	HKeyClass    windows.Handle
	DwHotKey     uint32
	HIcon        windows.Handle
	HProcess     windows.Handle
}

var (
	modShell32           = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW  = modShell32.NewProc("ShellExecuteExW")
)

// IsElevated reports whether the current process token is elevated (high IL admin).
func IsElevated() (bool, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, err
	}
	defer token.Close()

	var elevation uint32
	var outLen uint32
	err = windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&outLen,
	)
	if err != nil {
		return false, err
	}
	return elevation != 0, nil
}

// RelaunchElevated re-runs the current executable with runas and the given args
// (excluding argv0). Waits for the elevated process and returns its exit code.
func RelaunchElevated(args []string) (exitCode int, err error) {
	exe, err := os.Executable()
	if err != nil {
		return 1, fmt.Errorf("resolve executable: %w", err)
	}
	return RunElevated(exe, args)
}

// RunElevated launches exe with runas and waits for exit.
func RunElevated(exe string, args []string) (exitCode int, err error) {
	params := quoteArgs(args)
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return 1, err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 1, err
	}
	paramPtr, err := windows.UTF16PtrFromString(params)
	if err != nil {
		return 1, err
	}

	info := shellExecuteInfoW{
		FMask:        seeMaskNoCloseProcess,
		LpVerb:       verb,
		LpFile:       file,
		LpParameters: paramPtr,
		NShow:        swHide,
	}
	info.CbSize = uint32(unsafe.Sizeof(info))

	r1, _, e1 := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if r1 == 0 {
		if e1 != windows.ERROR_SUCCESS {
			return 1, fmt.Errorf("elevation failed: %w", e1)
		}
		return 1, fmt.Errorf("elevation failed")
	}
	if info.HProcess == 0 {
		return 1, fmt.Errorf("elevation failed: no process handle (UAC canceled?)")
	}
	defer windows.CloseHandle(info.HProcess)

	event, err := windows.WaitForSingleObject(info.HProcess, windows.INFINITE)
	if err != nil {
		return 1, err
	}
	if event != windows.WAIT_OBJECT_0 {
		return 1, fmt.Errorf("wait for elevated process failed")
	}

	var code uint32
	if err := windows.GetExitCodeProcess(info.HProcess, &code); err != nil {
		return 1, err
	}
	return int(code), nil
}

func quoteArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if a == "" {
			parts = append(parts, `""`)
			continue
		}
		if strings.IndexAny(a, " \t\"") >= 0 {
			escaped := strings.ReplaceAll(a, `"`, `\"`)
			parts = append(parts, `"`+escaped+`"`)
			continue
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

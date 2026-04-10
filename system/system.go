package system

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	user32                   = syscall.NewLazyDLL("user32.dll")
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	getForegroundWindow      = user32.NewProc("GetForegroundWindow")
	getWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	getCurrentProcessId      = kernel32.NewProc("GetCurrentProcessId")
	getConsoleWindow         = kernel32.NewProc("GetConsoleWindow")
)

func IsAppInForeground() bool {
	// Get foreground window handle.
	fgWindow, _, _ := getForegroundWindow.Call()
	if fgWindow == 0 {
		return false
	}

	// If we have a console window handle, compare window handles directly.
	// This is more reliable than PID checks for console-hosted processes.
	consoleWindow, _, _ := getConsoleWindow.Call()
	if consoleWindow != 0 {
		if fgWindow == consoleWindow {
			return true
		}
	}

	var fgPID uint32
	getWindowThreadProcessId.Call(fgWindow, uintptr(unsafe.Pointer(&fgPID)))
	if fgPID == 0 {
		return false
	}

	// Compare to current PID first.
	pid, _, _ := getCurrentProcessId.Call()
	selfPID := uint32(pid)
	if fgPID == selfPID {
		return true
	}

	// For terminal-hosted processes, the foreground PID may be a parent host
	// process (pwsh/cmd/terminal). Walk ancestors and allow that as foreground.
	return isAncestorPID(selfPID, fgPID, 6)
}

func isAncestorPID(pid, target uint32, maxDepth int) bool {
	current := pid
	for i := 0; i < maxDepth && current != 0; i++ {
		parent, ok := parentPIDOf(current)
		if !ok || parent == 0 {
			return false
		}
		if parent == target {
			return true
		}
		current = parent
	}
	return false
}

func parentPIDOf(pid uint32) (uint32, bool) {
	h, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, false
	}
	defer syscall.CloseHandle(h)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = syscall.Process32First(h, &entry)
	for err == nil {
		if entry.ProcessID == pid {
			return entry.ParentProcessID, true
		}
		err = syscall.Process32Next(h, &entry)
	}

	return 0, false
}

func IsProcessStartedByExplorer() bool {
	ppid := os.Getppid()
	if ppid == 0 {
		return false
	}

	// Create a snapshot of processes to find the parent's name
	h, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	// Iterate through processes in the snapshot
	err = syscall.Process32First(h, &entry)
	for err == nil {
		if int(entry.ProcessID) == ppid {
			// Convert the executable name from the entry to a string
			name := syscall.UTF16ToString(entry.ExeFile[:])
			return strings.ToLower(name) == "explorer.exe"
		}
		err = syscall.Process32Next(h, &entry)
	}

	return false
}

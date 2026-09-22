//go:build windows

package system

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

const eventModifyState = 0x0002

func processImagePath(pid uint32) (string, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)

	var buf [1024]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil || size == 0 {
		return "", false
	}
	return windows.UTF16ToString(buf[:size]), true
}

// ParentProcessImagePath returns the full image path of the immediate parent.
// Empty when the parent cannot be opened (exited, access denied).
func ParentProcessImagePath() string {
	ppid := uint32(os.Getppid())
	if ppid == 0 {
		return ""
	}
	img, ok := processImagePath(ppid)
	if !ok {
		return ""
	}
	return img
}

// ListAncestorImagePaths walks parents (parent first), best-effort, max 32 hops.
func ListAncestorImagePaths() []string {
	pid := uint32(os.Getpid())
	out := make([]string, 0, 8)
	var seen [32]uint32
	seenLen := 0
	for hop := 0; hop < 32; hop++ {
		parent, ok := parentPIDOf(pid)
		if !ok || parent == 0 || parent == pid {
			break
		}
		dup := false
		for i := 0; i < seenLen; i++ {
			if seen[i] == parent {
				dup = true
				break
			}
		}
		if dup {
			break
		}
		if seenLen < len(seen) {
			seen[seenLen] = parent
			seenLen++
		}
		if img, ok := processImagePath(parent); ok && img != "" {
			out = append(out, img)
		}
		pid = parent
	}
	return out
}

// SignalNamedEvent sets a Win32 named event. No-op on empty name or failure.
func SignalNamedEvent(name string) {
	if name == "" {
		return
	}
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	h, err := windows.OpenEvent(eventModifyState, false, n)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_ = windows.SetEvent(h)
}

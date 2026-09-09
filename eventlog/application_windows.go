//go:build windows

package eventlog

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const (
	classicApplicationSource = "Application"

	eventlogErrorType       = uint16(0x0001)
	eventlogWarningType     = uint16(0x0002)
	eventlogInformationType = uint16(0x0004)
)

// WriteApplicationWarning writes a classic Application log Warning using the
// built-in Application source (no custom source registration).
func WriteApplicationWarning(eventID uint32, message string) error {
	return writeApplicationEvent(eventlogWarningType, eventID, message)
}

// WriteApplicationError writes a classic Application log Error using the
// built-in Application source (no custom source registration).
func WriteApplicationError(eventID uint32, message string) error {
	return writeApplicationEvent(eventlogErrorType, eventID, message)
}

func writeApplicationEvent(eventType uint16, eventID uint32, message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}

	if err := reportEventNative(eventType, eventID, message); err == nil {
		return nil
	} else {
		logRuntimeDiagnostic(fmt.Sprintf("classic ReportEvent failed (event_id=%d): %v; trying PowerShell fallback", eventID, err))
	}

	return writeApplicationEventPowerShell(eventType, eventID, message)
}

func reportEventNative(eventType uint16, eventID uint32, message string) error {
	source, err := windows.UTF16PtrFromString(classicApplicationSource)
	if err != nil {
		return err
	}
	handle, err := windows.RegisterEventSource(nil, source)
	if err != nil {
		return err
	}
	defer windows.DeregisterEventSource(handle)

	msg, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return err
	}
	ptrs := []*uint16{msg}
	return windows.ReportEvent(
		handle,
		eventType,
		0,
		eventID,
		0,
		1,
		0,
		&ptrs[0],
		nil,
	)
}

func writeApplicationEventPowerShell(eventType uint16, eventID uint32, message string) error {
	entryType := "Warning"
	switch eventType {
	case eventlogErrorType:
		entryType = "Error"
	case eventlogInformationType:
		entryType = "Information"
	}

	tmp, err := os.CreateTemp("", "nvm-appevent-*.txt")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_, writeErr := tmp.WriteString(message)
	closeErr := tmp.Close()
	defer os.Remove(tmpPath)
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}

	ps := fmt.Sprintf(
		"try { Write-EventLog -LogName Application -Source Application -EntryType %s -EventId %d -Message (Get-Content -Raw -LiteralPath '%s') } catch { exit 1 }",
		entryType,
		eventID,
		strings.ReplaceAll(tmpPath, "'", "''"),
	)
	cmd := exec.Command(
		filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("%w: %s", err, trimmed)
		}
		return err
	}
	return nil
}

// WriteApplicationWarningThrottled writes at most once per interval using stampPath.
// Returns true when an event was written.
func WriteApplicationWarningThrottled(eventID uint32, message, stampPath string, interval time.Duration) (bool, error) {
	if interval <= 0 {
		interval = time.Hour
	}
	if !shouldWriteThrottled(stampPath, interval) {
		return false, nil
	}
	if err := WriteApplicationWarning(eventID, message); err != nil {
		return false, err
	}
	_ = touchThrottleStamp(stampPath)
	return true, nil
}

func shouldWriteThrottled(stampPath string, interval time.Duration) bool {
	if strings.TrimSpace(stampPath) == "" {
		return true
	}
	info, err := os.Stat(stampPath)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) >= interval
}

func touchThrottleStamp(stampPath string) error {
	if strings.TrimSpace(stampPath) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(stampPath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(stampPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, _ = f.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
	return f.Close()
}

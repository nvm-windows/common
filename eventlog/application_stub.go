//go:build !windows

package eventlog

import "time"

// WriteApplicationWarning is a no-op on non-Windows.
func WriteApplicationWarning(eventID uint32, message string) error {
	return nil
}

// WriteApplicationError is a no-op on non-Windows.
func WriteApplicationError(eventID uint32, message string) error {
	return nil
}

// WriteApplicationWarningThrottled is a no-op on non-Windows.
func WriteApplicationWarningThrottled(eventID uint32, message, stampPath string, interval time.Duration) (bool, error) {
	return false, nil
}

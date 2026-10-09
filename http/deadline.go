package http

import (
	"context"
	"errors"
	"strings"
)

// IsDeadline reports whether err is an HTTP client timeout or context deadline.
func IsDeadline(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "deadline exceeded") || strings.Contains(s, "client.timeout")
}

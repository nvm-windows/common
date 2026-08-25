package verify

import (
	"fmt"
	"path/filepath"
	"strings"
)

// NormalizeThumbprint strips separators and uppercases hex for comparison.
func NormalizeThumbprint(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r - 32)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeThumbprints trims and normalizes a pin list, dropping empties.
func NormalizeThumbprints(pins []string) []string {
	out := make([]string, 0, len(pins))
	for _, pin := range pins {
		n := NormalizeThumbprint(pin)
		if n == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}

// IsAllowedThumbprint reports whether thumb matches any pin (empty pins = allow all).
func IsAllowedThumbprint(thumb string, pins []string) bool {
	normalizedPins := NormalizeThumbprints(pins)
	if len(normalizedPins) == 0 {
		return true
	}
	candidate := NormalizeThumbprint(thumb)
	if candidate == "" {
		return false
	}
	for _, pin := range normalizedPins {
		if candidate == pin {
			return true
		}
	}
	return false
}

func enforceAllowedThumbprints(exePath string, pins []string) error {
	normalized := NormalizeThumbprints(pins)
	if len(normalized) == 0 {
		return nil
	}
	thumb := SignerThumbprint(exePath)
	if thumb == "" {
		return fmt.Errorf("unable to resolve signer thumbprint for %s", filepath.Base(exePath))
	}
	if !IsAllowedThumbprint(thumb, normalized) {
		return fmt.Errorf(
			"signer thumbprint %q is not pinned (allowed thumbprints configured)",
			NormalizeThumbprint(thumb),
		)
	}
	return nil
}

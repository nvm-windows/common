package verify

import (
	"common/settings"
	"strings"
)

// RevocationMode controls WinVerifyTrust certificate revocation checks.
type RevocationMode string

const (
	// RevocationDisabled skips CRL/OCSP (legacy behavior).
	RevocationDisabled RevocationMode = "disabled"
	// RevocationCached checks revocation using only the local URL cache (no network).
	RevocationCached RevocationMode = "cached"
	// RevocationOnline may retrieve CRL/OCSP over the network (seed/install paths only).
	RevocationOnline RevocationMode = "online"
)

// ParseRevocationMode normalizes a setting value. Unknown/empty → defaultMode.
func ParseRevocationMode(raw string, defaultMode RevocationMode) RevocationMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(RevocationDisabled), "none", "off", "0":
		return RevocationDisabled
	case string(RevocationCached), "cache", "cache_only", "cache-only":
		return RevocationCached
	case string(RevocationOnline), "wholechain", "full":
		return RevocationOnline
	default:
		if defaultMode == "" {
			return RevocationOnline
		}
		return defaultMode
	}
}

// ClampRuntimeRevocationMode never allows online checks on shim hot/cold paths.
// online → cached so WinVerifyTrust stays local (typically sub-ms on top of chain verify).
func ClampRuntimeRevocationMode(mode RevocationMode) RevocationMode {
	if mode == RevocationOnline {
		return RevocationCached
	}
	if mode == "" {
		return RevocationCached
	}
	return mode
}

// EffectiveSeedRevocationMode is for install / SignNodeCache / activation / sync.
// Default online; AirGapped forces cached when online would be selected.
func EffectiveSeedRevocationMode() RevocationMode {
	cfg := settings.Global()
	mode := ParseRevocationMode(cfg.AuthenticodeRevocation, RevocationOnline)
	if cfg.AirGapped && mode == RevocationOnline {
		return RevocationCached
	}
	return mode
}

// EffectiveRuntimeRevocationMode is for shim WinVerifyTrust (cache miss / delegated .exe).
// Never online — preserves ≤1–2ms budget on warm paths (warm path skips WinVerifyTrust entirely).
func EffectiveRuntimeRevocationMode() RevocationMode {
	return ClampRuntimeRevocationMode(EffectiveSeedRevocationMode())
}

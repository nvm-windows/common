package license

import (
	"common/settings"
	"common/token"
	"strings"
	"time"
)

const (
	// LicenseVerifyMaxAge is how long commercial entitlements stay trusted after
	// the last successful online AccessToken verification.
	LicenseVerifyMaxAge = 30 * 24 * time.Hour
	// LicenseVerifyWarnAge is when sync starts warning that revalidation is overdue.
	LicenseVerifyWarnAge = 7 * 24 * time.Hour
	// LicenseVerifyAttemptInterval throttles online verify attempts (~2x/week).
	LicenseVerifyAttemptInterval = 84 * time.Hour // 3.5 days
)

var (
	airGappedFn = func() bool { return settings.Global().AirGapped }
	verifiedAtFn = func() string { return strings.TrimSpace(settings.Global().LastLicenseVerifiedAt) }
	verifyAttemptAtFn = func() string {
		return strings.TrimSpace(settings.Global().LastLicenseVerifyAttemptAt)
	}
	putSettingFn   = settings.Put
	nowFn          = time.Now
	setAccessToken = token.Set
)

// CommercialTrustOK reports whether commercial entitlements may be granted based
// on periodic online revalidation. AirGapped hosts skip this check (offline JWKS
// + JWT exp/grace only). Missing LastLicenseVerifiedAt while online is not trusted.
func CommercialTrustOK(now time.Time) bool {
	if airGappedFn() {
		return true
	}
	stamp, ok := parseRFC3339UTC(verifiedAtFn())
	if !ok {
		return false
	}
	return !now.After(stamp.Add(LicenseVerifyMaxAge))
}

// LicenseVerifyAge returns how long since the last successful online verify.
// ok is false when AirGapped or no stamp exists.
func LicenseVerifyAge(now time.Time) (age time.Duration, ok bool) {
	if airGappedFn() {
		return 0, false
	}
	stamp, ok := parseRFC3339UTC(verifiedAtFn())
	if !ok {
		return 0, false
	}
	if now.Before(stamp) {
		return 0, true
	}
	return now.Sub(stamp), true
}

// LicenseVerifyAttemptDue reports whether an online verify attempt should run.
// Missing attempt stamp or missing success stamp → due immediately.
func LicenseVerifyAttemptDue(now time.Time) bool {
	if airGappedFn() {
		return false
	}
	if strings.TrimSpace(verifiedAtFn()) == "" {
		return true
	}
	attempt, ok := parseRFC3339UTC(verifyAttemptAtFn())
	if !ok {
		return true
	}
	return !now.Before(attempt.Add(LicenseVerifyAttemptInterval))
}

// StampLicenseVerified records a successful online AccessToken verification.
func StampLicenseVerified(now time.Time) error {
	return putSettingFn("last_license_verified_at", now.UTC().Format(time.RFC3339))
}

// StampLicenseVerifyAttempt records that an online verify was tried.
func StampLicenseVerifyAttempt(now time.Time) error {
	return putSettingFn("last_license_verify_attempt_at", now.UTC().Format(time.RFC3339))
}

// VerifyAndStampAccessToken runs token.Set and stamps success on OK.
// Does not clear AccessToken on failure.
func VerifyAndStampAccessToken(raw string, now time.Time) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if err := StampLicenseVerifyAttempt(now); err != nil {
		return err
	}
	if err := setAccessToken(raw); err != nil {
		return err
	}
	return StampLicenseVerified(now)
}

func parseRFC3339UTC(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

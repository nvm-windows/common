package license

import (
	"errors"
	"testing"
	"time"
)

func TestCommercialTrustOK(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	origAir, origVerified := airGappedFn, verifiedAtFn
	t.Cleanup(func() {
		airGappedFn = origAir
		verifiedAtFn = origVerified
	})

	t.Run("airgapped always ok", func(t *testing.T) {
		airGappedFn = func() bool { return true }
		verifiedAtFn = func() string { return "" }
		if !CommercialTrustOK(now) {
			t.Fatal("expected AirGapped trust OK")
		}
	})

	t.Run("missing stamp not trusted", func(t *testing.T) {
		airGappedFn = func() bool { return false }
		verifiedAtFn = func() string { return "" }
		if CommercialTrustOK(now) {
			t.Fatal("missing stamp must not trust")
		}
	})

	t.Run("fresh stamp trusted", func(t *testing.T) {
		airGappedFn = func() bool { return false }
		verifiedAtFn = func() string { return now.Add(-24 * time.Hour).Format(time.RFC3339) }
		if !CommercialTrustOK(now) {
			t.Fatal("expected fresh stamp trusted")
		}
	})

	t.Run("stale stamp not trusted", func(t *testing.T) {
		airGappedFn = func() bool { return false }
		verifiedAtFn = func() string {
			return now.Add(-(LicenseVerifyMaxAge + time.Hour)).Format(time.RFC3339)
		}
		if CommercialTrustOK(now) {
			t.Fatal("stale stamp must not trust")
		}
	})

	t.Run("exactly 30d still trusted", func(t *testing.T) {
		airGappedFn = func() bool { return false }
		verifiedAtFn = func() string { return now.Add(-LicenseVerifyMaxAge).Format(time.RFC3339) }
		if !CommercialTrustOK(now) {
			t.Fatal("age == 30d should still trust")
		}
	})
}

func TestLicenseVerifyAttemptDue(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	origAir, origVerified, origAttempt := airGappedFn, verifiedAtFn, verifyAttemptAtFn
	t.Cleanup(func() {
		airGappedFn = origAir
		verifiedAtFn = origVerified
		verifyAttemptAtFn = origAttempt
	})

	airGappedFn = func() bool { return false }
	verifiedAtFn = func() string { return now.Add(-time.Hour).Format(time.RFC3339) }

	t.Run("missing attempt due", func(t *testing.T) {
		verifyAttemptAtFn = func() string { return "" }
		if !LicenseVerifyAttemptDue(now) {
			t.Fatal("expected due")
		}
	})

	t.Run("recent attempt not due", func(t *testing.T) {
		verifyAttemptAtFn = func() string { return now.Add(-time.Hour).Format(time.RFC3339) }
		if LicenseVerifyAttemptDue(now) {
			t.Fatal("expected not due")
		}
	})

	t.Run("interval elapsed due", func(t *testing.T) {
		verifyAttemptAtFn = func() string {
			return now.Add(-(LicenseVerifyAttemptInterval + time.Minute)).Format(time.RFC3339)
		}
		if !LicenseVerifyAttemptDue(now) {
			t.Fatal("expected due after interval")
		}
	})

	t.Run("missing success stamp due immediately", func(t *testing.T) {
		verifiedAtFn = func() string { return "" }
		verifyAttemptAtFn = func() string { return now.Format(time.RFC3339) }
		if !LicenseVerifyAttemptDue(now) {
			t.Fatal("missing success stamp must force attempt")
		}
	})

	t.Run("airgapped never due", func(t *testing.T) {
		airGappedFn = func() bool { return true }
		verifiedAtFn = func() string { return "" }
		verifyAttemptAtFn = func() string { return "" }
		if LicenseVerifyAttemptDue(now) {
			t.Fatal("AirGapped must skip attempts")
		}
	})
}

func TestVerifyAndStampAccessTokenLeavesTokenOnFailure(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	puts := map[string]string{}
	origPut, origSet := putSettingFn, setAccessToken
	t.Cleanup(func() {
		putSettingFn = origPut
		setAccessToken = origSet
	})

	putSettingFn = func(name string, value interface{}) error {
		puts[name] = value.(string)
		return nil
	}
	setAccessToken = func(string) error {
		return errors.New("revoked")
	}

	err := VerifyAndStampAccessToken("tok", now)
	if err == nil {
		t.Fatal("expected verify error")
	}
	if _, ok := puts["last_license_verify_attempt_at"]; !ok {
		t.Fatal("expected attempt stamp")
	}
	if _, ok := puts["last_license_verified_at"]; ok {
		t.Fatal("must not stamp success on failure")
	}
}

func TestVerifyAndStampAccessTokenSuccess(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	puts := map[string]string{}
	origPut, origSet := putSettingFn, setAccessToken
	t.Cleanup(func() {
		putSettingFn = origPut
		setAccessToken = origSet
	})

	putSettingFn = func(name string, value interface{}) error {
		puts[name] = value.(string)
		return nil
	}
	setAccessToken = func(string) error { return nil }

	if err := VerifyAndStampAccessToken("tok", now); err != nil {
		t.Fatal(err)
	}
	if puts["last_license_verified_at"] != now.UTC().Format(time.RFC3339) {
		t.Fatalf("verified stamp = %q", puts["last_license_verified_at"])
	}
}

func withCommercialTrustOK(t *testing.T) {
	t.Helper()
	origAir, origVerified := airGappedFn, verifiedAtFn
	airGappedFn = func() bool { return false }
	verifiedAtFn = func() string { return time.Now().UTC().Format(time.RFC3339) }
	t.Cleanup(func() {
		airGappedFn = origAir
		verifiedAtFn = origVerified
	})
}

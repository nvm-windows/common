package license

import (
	"strings"
	"testing"
	"time"
)

func TestCalendarDaysUntilExpiry(t *testing.T) {
	loc := time.FixedZone("CT", -6*3600)
	now := time.Date(2026, 8, 8, 22, 15, 0, 0, loc)
	cases := []struct {
		exp  time.Time
		want int
	}{
		{time.Date(2026, 8, 15, 9, 0, 0, 0, loc), 7},
		{time.Date(2026, 8, 11, 1, 0, 0, 0, loc), 3},
		{time.Date(2026, 8, 9, 23, 0, 0, 0, loc), 1},
		{time.Date(2026, 8, 8, 1, 0, 0, 0, loc), 0},
		{time.Date(2026, 8, 7, 23, 0, 0, 0, loc), -1},
		{time.Date(2026, 8, 1, 12, 0, 0, 0, loc), -7},
		{time.Date(2026, 7, 31, 12, 0, 0, 0, loc), -8},
	}
	for _, tt := range cases {
		if got := CalendarDaysUntilExpiry(now, tt.exp); got != tt.want {
			t.Fatalf("days(now=%s exp=%s)=%d want %d", now, tt.exp, got, tt.want)
		}
	}
}

func TestExpiryNoticeMilestones(t *testing.T) {
	loc := time.FixedZone("CT", -6*3600)
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, loc)
	exp := time.Date(2026, 8, 15, 18, 0, 0, 0, loc) // 7 days

	n, ok := expiryNotice(now, exp, "governance")
	if !ok || !strings.Contains(n.Title, "7 days") || !strings.HasSuffix(n.DedupeKey, "|pre7") {
		t.Fatalf("pre7 notice = %+v ok=%v", n, ok)
	}

	n, ok = expiryNotice(now, time.Date(2026, 8, 11, 18, 0, 0, 0, loc), "compliance")
	if !ok || !strings.Contains(n.Title, "3 days") || !strings.Contains(n.Body, "Audit") {
		t.Fatalf("pre3 notice = %+v ok=%v", n, ok)
	}

	n, ok = expiryNotice(now, time.Date(2026, 8, 9, 18, 0, 0, 0, loc), "governance")
	if !ok || !strings.Contains(n.Title, "tomorrow") {
		t.Fatalf("pre1 notice = %+v ok=%v", n, ok)
	}

	n, ok = expiryNotice(now, time.Date(2026, 8, 8, 23, 0, 0, 0, loc), "governance")
	if !ok || !strings.Contains(n.Title, "today") || !strings.HasSuffix(n.DedupeKey, "|day0") {
		t.Fatalf("day0 notice = %+v ok=%v", n, ok)
	}
}

func TestExpiryNoticeGraceDaily(t *testing.T) {
	loc := time.FixedZone("CT", -6*3600)
	exp := time.Date(2026, 8, 8, 9, 0, 0, 0, loc)
	now := time.Date(2026, 8, 9, 8, 0, 0, 0, loc) // days=-1
	n, ok := expiryNotice(now, exp, "governance")
	if !ok || n.Title != "NVM for Windows license expired" {
		t.Fatalf("grace notice = %+v ok=%v", n, ok)
	}
	if !strings.Contains(n.DedupeKey, "|grace|2026-08-09") {
		t.Fatalf("dedupe key = %q", n.DedupeKey)
	}
	if !strings.Contains(n.Body, "7 more day(s)") {
		t.Fatalf("body = %q", n.Body)
	}

	last := time.Date(2026, 8, 15, 8, 0, 0, 0, loc) // days=-7
	n, ok = expiryNotice(last, exp, "compliance")
	if !ok || !strings.Contains(n.Body, "1 more day(s)") {
		t.Fatalf("last grace = %+v ok=%v", n, ok)
	}

	after := time.Date(2026, 8, 16, 8, 0, 0, 0, loc)
	if _, ok := expiryNotice(after, exp, "governance"); ok {
		t.Fatal("post-grace should not notify")
	}

	far := time.Date(2026, 7, 1, 8, 0, 0, 0, loc)
	if _, ok := expiryNotice(far, exp, "governance"); ok {
		t.Fatal("more than 7 days out should not notify")
	}
}

func TestExpiryNoticeForTokenSkipsCommunity(t *testing.T) {
	raw := mustMintAccessToken(t, "community", false)
	if _, ok := ExpiryNoticeForToken(raw, time.Now()); ok {
		t.Fatal("community token must not produce expiry notice")
	}
}

func TestExpiryNoticeForTokenCertifiedPlans(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	exp := time.Date(2026, 8, 15, 18, 0, 0, 0, time.UTC)
	for _, plan := range []string{"governance", "compliance"} {
		raw := mustMintAccessTokenExpiringAt(t, plan, exp)
		n, ok := ExpiryNoticeForToken(raw, now)
		if !ok || !strings.HasSuffix(n.DedupeKey, "|pre7") {
			t.Fatalf("%s notice = %+v ok=%v", plan, n, ok)
		}
	}
}

func TestWithinFeatureWindowGrace(t *testing.T) {
	now := time.Now()
	raw := mustMintAccessTokenExpiringAt(t, "governance", now.Add(-time.Hour))
	if _, ok := commercialLicenseType(raw); !ok {
		t.Fatal("expired 1h ago should still authorize features during grace")
	}
	raw = mustMintAccessTokenExpiringAt(t, "governance", now.Add(-FeatureGracePeriod-time.Hour))
	if _, ok := commercialLicenseType(raw); ok {
		t.Fatal("expired beyond grace must not authorize features")
	}
}

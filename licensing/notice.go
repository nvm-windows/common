package license

import (
	"fmt"
	"strings"
	"time"
)

// CalendarDaysUntilExpiry is whole local calendar days from now's date to exp's date.
// Positive = future, 0 = expires today, negative = already past.
func CalendarDaysUntilExpiry(now, exp time.Time) int {
	loc := now.Location()
	n := startOfLocalDay(now.In(loc))
	e := startOfLocalDay(exp.In(loc))
	return int(e.Sub(n).Hours() / 24)
}

func startOfLocalDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// ExpiryNotice describes a desktop warning for certified Audit/Governance licenses.
type ExpiryNotice struct {
	Title     string
	Body      string
	DedupeKey string
}

// ExpiryNoticeForToken returns a notice when a certified commercial license is in
// the 7/3/1-day pre-expiry window, expires today, or is inside the 7-day grace
// period. Community/tmp/missing tokens yield ok=false.
func ExpiryNoticeForToken(raw string, now time.Time) (ExpiryNotice, bool) {
	claims, ok := parseCommercialClaims(raw)
	if !ok {
		return ExpiryNotice{}, false
	}
	plan := strings.ToLower(strings.TrimSpace(claims.LicenseType()))
	exp, ok := expirationTime(claims)
	if !ok {
		return ExpiryNotice{}, false
	}
	return expiryNotice(now, exp, plan)
}

func expiryNotice(now, exp time.Time, plan string) (ExpiryNotice, bool) {
	days := CalendarDaysUntilExpiry(now, exp)
	expKey := exp.UTC().Format(time.RFC3339)
	edition := editionLabel(plan)
	expLocal := exp.In(now.Location()).Format("January 2, 2006")

	switch {
	case days == 7:
		return ExpiryNotice{
			Title:     "NVM for Windows license expires in 7 days",
			Body:      fmt.Sprintf("Your %s license expires on %s. Renew with nvm license set to keep certified features.", edition, expLocal),
			DedupeKey: expKey + "|pre7",
		}, true
	case days == 3:
		return ExpiryNotice{
			Title:     "NVM for Windows license expires in 3 days",
			Body:      fmt.Sprintf("Your %s license expires on %s. Renew with nvm license set to keep certified features.", edition, expLocal),
			DedupeKey: expKey + "|pre3",
		}, true
	case days == 1:
		return ExpiryNotice{
			Title:     "NVM for Windows license expires tomorrow",
			Body:      fmt.Sprintf("Your %s license expires on %s. Renew with nvm license set to keep certified features.", edition, expLocal),
			DedupeKey: expKey + "|pre1",
		}, true
	case days == 0:
		return ExpiryNotice{
			Title:     "NVM for Windows license expires today",
			Body:      fmt.Sprintf("Your %s license expires today (%s). A 7-day grace period follows expiry. Renew with nvm license set.", edition, expLocal),
			DedupeKey: expKey + "|day0",
		}, true
	case days <= -1 && days >= -7:
		// Inclusive calendar days left through expDate+7 (days=-1 → 7, days=-7 → 1).
		remain := 8 + days
		return ExpiryNotice{
			Title:     "NVM for Windows license expired",
			Body:      fmt.Sprintf("Your %s license expired on %s. Certified features remain available for %d more day(s). Renew with nvm license set.", edition, expLocal, remain),
			DedupeKey: expKey + "|grace|" + startOfLocalDay(now).Format("2006-01-02"),
		}, true
	default:
		return ExpiryNotice{}, false
	}
}

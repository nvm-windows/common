package settings

import (
	"strings"
	"testing"
)

func TestPut_AuditsLicenseKeyChangeWithoutValue(t *testing.T) {
	const accessToken = "header.payload.signature"

	message, ok := ChangeAuditMessage("access_token", nil, accessToken)
	if !ok {
		t.Fatal("expected access_token change to be auditable")
	}
	if message != "License key changed." {
		t.Fatalf("expected license key audit message, got %q", message)
	}
	if strings.Contains(message, accessToken) {
		t.Fatalf("expected audit message to omit raw token, got %q", message)
	}
}

func TestPut_DoesNotAuditUnchangedLicenseKey(t *testing.T) {
	const accessToken = "header.payload.signature"

	if message, ok := ChangeAuditMessage("access_token", accessToken, accessToken); ok {
		t.Fatalf("expected no audit message for unchanged token, got %q", message)
	}
}

func TestDel_AuditsLicenseKeyClear(t *testing.T) {
	message, ok := DeletionAuditMessage("access_token", "header.payload.signature")
	if !ok {
		t.Fatal("expected access_token deletion to be auditable")
	}
	if message != "License key cleared." {
		t.Fatalf("expected license key cleared audit message, got %q", message)
	}
}

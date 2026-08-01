package settings

import (
	"strings"
	"testing"
)

func TestPut_AuditsAccessTokenChangeWithoutValue(t *testing.T) {
	const accessToken = "header.payload.signature"

	message, ok := ChangeAuditMessage("access_token", nil, accessToken)
	if !ok {
		t.Fatal("expected access_token change to be auditable")
	}
	if message != "Access token changed." {
		t.Fatalf("expected access token audit message, got %q", message)
	}
	if strings.Contains(message, accessToken) {
		t.Fatalf("expected audit message to omit raw token, got %q", message)
	}
}

func TestPut_DoesNotAuditUnchangedAccessToken(t *testing.T) {
	const accessToken = "header.payload.signature"

	if message, ok := ChangeAuditMessage("access_token", accessToken, accessToken); ok {
		t.Fatalf("expected no audit message for unchanged token, got %q", message)
	}
}

func TestDel_AuditsAccessTokenClear(t *testing.T) {
	message, ok := DeletionAuditMessage("access_token", "header.payload.signature")
	if !ok {
		t.Fatal("expected access_token deletion to be auditable")
	}
	if message != "Access token cleared." {
		t.Fatalf("expected access token cleared audit message, got %q", message)
	}
}

func TestPut_AuditsAccessKeyChangeWithoutValue(t *testing.T) {
	const accessKey = "license-key-material"

	message, ok := ChangeAuditMessage("access_key", nil, accessKey)
	if !ok {
		t.Fatal("expected access_key change to be auditable")
	}
	if message != "License key changed." {
		t.Fatalf("expected license key audit message, got %q", message)
	}
}

func TestDel_AuditsAccessKeyClear(t *testing.T) {
	message, ok := DeletionAuditMessage("access_key", "license-key-material")
	if !ok {
		t.Fatal("expected access_key deletion to be auditable")
	}
	if message != "License key cleared." {
		t.Fatalf("expected license key cleared audit message, got %q", message)
	}
}

func TestAccessKeyIsSecret(t *testing.T) {
	if !IsSecret("access_key") {
		t.Fatal("expected access_key to be secret")
	}
}

package eventlog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEnrichStructuredPayloadAddsNVMVersion(t *testing.T) {
	prev := ProductVersion
	ProductVersion = "2.1.0-beta.9"
	t.Cleanup(func() { ProductVersion = prev })

	got := enrichStructuredPayload(map[string]any{"action": "upgrade"})
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("got %T", got)
	}
	if m["nvm_version"] != "2.1.0-beta.9" {
		t.Fatalf("nvm_version = %v", m["nvm_version"])
	}
	if m["action"] != "upgrade" {
		t.Fatalf("action = %v", m["action"])
	}
}

func TestEnrichStructuredPayloadPreservesCallerNVMVersion(t *testing.T) {
	prev := ProductVersion
	ProductVersion = "2.1.0-beta.9"
	t.Cleanup(func() { ProductVersion = prev })

	got := enrichStructuredPayload(map[string]any{"nvm_version": "9.9.9"})
	m := got.(map[string]any)
	if m["nvm_version"] != "9.9.9" {
		t.Fatalf("caller nvm_version overwritten: %v", m["nvm_version"])
	}
}

func TestEnrichStructuredPayloadNilBecomesObject(t *testing.T) {
	prev := ProductVersion
	ProductVersion = "2.0.1"
	t.Cleanup(func() { ProductVersion = prev })

	got := enrichStructuredPayload(nil)
	m, ok := got.(map[string]any)
	if !ok || m["nvm_version"] != "2.0.1" {
		t.Fatalf("nil enrich = %#v", got)
	}
}

func TestEnrichStructuredPayloadJSONObject(t *testing.T) {
	prev := ProductVersion
	ProductVersion = "2.1.0"
	t.Cleanup(func() { ProductVersion = prev })

	raw := json.RawMessage(`{"foo":"bar"}`)
	got := enrichStructuredPayload(raw)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"nvm_version":"2.1.0"`) {
		t.Fatalf("json enrich = %s", encoded)
	}
	if !strings.Contains(string(encoded), `"foo":"bar"`) {
		t.Fatalf("lost foo: %s", encoded)
	}
}

func TestEnrichStructuredPayloadSkipsWhenUnset(t *testing.T) {
	prev := ProductVersion
	ProductVersion = ""
	t.Cleanup(func() { ProductVersion = prev })

	in := map[string]any{"a": 1}
	got := enrichStructuredPayload(in)
	m := got.(map[string]any)
	if _, ok := m["nvm_version"]; ok {
		t.Fatal("unexpected nvm_version when ProductVersion empty")
	}
}

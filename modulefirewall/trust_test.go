package modulefirewall

import (
	"strings"
	"testing"
)

func TestStripHTTPSURLs(t *testing.T) {
	got := StripHTTPSURLs([]string{"eslint", "https://policy.example/trust", "NOT ALL", ""})
	if len(got) != 2 || got[0] != "eslint" || got[1] != "NOT ALL" {
		t.Fatalf("got %#v", got)
	}
}

func TestEvaluateTrustedModules_AllLocalNoHTTP(t *testing.T) {
	var hits int
	prev := evaluateRemoteRequestFn
	evaluateRemoteRequestFn = func(endpoint string, modules []PackageSpec, opts RemoteRequestOptions) RemoteResult {
		hits++
		return RemoteResult{Allowed: true, Status: 200}
	}
	defer func() { evaluateRemoteRequestFn = prev }()

	rules := []string{"NOT ALL", "eslint", "https://policy.example/trust"}
	res := EvaluateTrustedModules([]PackageSpec{{Name: "eslint", Raw: "eslint"}}, rules, RemoteTLSOptions{TimeoutSec: 2})
	if !res.Trusted {
		t.Fatalf("want trusted, got %#v", res)
	}
	if res.RemoteQueried || hits != 0 {
		t.Fatalf("HTTP should not run when locally trusted; hits=%d remote=%v", hits, res.RemoteQueried)
	}
}

func TestEvaluateTrustedModules_RemoteOnlyUntrusted(t *testing.T) {
	var gotMods []PackageSpec
	prev := evaluateRemoteRequestFn
	evaluateRemoteRequestFn = func(endpoint string, modules []PackageSpec, opts RemoteRequestOptions) RemoteResult {
		gotMods = append([]PackageSpec(nil), modules...)
		return RemoteResult{Allowed: true, Status: 200}
	}
	defer func() { evaluateRemoteRequestFn = prev }()

	rules := []string{"NOT ALL", "lodash", "https://policy.example/trust"}
	pkgs := []PackageSpec{
		{Name: "lodash", Raw: "lodash"},
		{Name: "eslint", Raw: "eslint"},
	}
	res := EvaluateTrustedModules(pkgs, rules, RemoteTLSOptions{TimeoutSec: 2})
	if !res.Trusted || !res.RemoteQueried {
		t.Fatalf("want trusted via remote, got %#v", res)
	}
	if len(gotMods) != 1 || gotMods[0].Name != "eslint" {
		t.Fatalf("want only eslint remoted, got %#v", gotMods)
	}
}

func TestEvaluateTrustedModules_NoResponseUntrustedMessage(t *testing.T) {
	prev := evaluateRemoteRequestFn
	evaluateRemoteRequestFn = func(endpoint string, modules []PackageSpec, opts RemoteRequestOptions) RemoteResult {
		return RemoteResult{
			Allowed:     false,
			Status:      0,
			Unreachable: true,
			ErrorMsg:    "The NVM firewall could not reach the remote authority at https://policy.example/trust because the connection timed out.",
		}
	}
	defer func() { evaluateRemoteRequestFn = prev }()

	rules := []string{"NOT ALL", "https://policy.example/trust"}
	res := EvaluateTrustedModules([]PackageSpec{{Name: "eslint", Raw: "eslint"}}, rules, RemoteTLSOptions{TimeoutSec: 1})
	if res.Trusted {
		t.Fatalf("want untrusted on no response")
	}
	if !res.RemoteQueried {
		t.Fatalf("want remote queried")
	}
	if !strings.Contains(res.Message, "could not reach the remote authority") {
		t.Fatalf("message=%q", res.Message)
	}
	if strings.Contains(res.Message, "HTTP 403") || strings.Contains(res.Message, "HTTP 200") {
		t.Fatalf("transport error should not mention 200/403: %q", res.Message)
	}
}

func TestIsPackageTrustedLocal_IgnoresURL(t *testing.T) {
	ok, err := IsPackageTrustedLocal(PackageSpec{Name: "eslint", Raw: "eslint"}, []string{"NOT ALL", "eslint", "https://policy.example/t"})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	ok, err = IsPackageTrustedLocal(PackageSpec{Name: "lodash", Raw: "lodash"}, []string{"NOT ALL", "eslint", "https://policy.example/t"})
	if err != nil || ok {
		t.Fatalf("lodash should be local-untrusted; ok=%v err=%v", ok, err)
	}
}

func TestIsPackageTrustedLocal_URLOnlyDenies(t *testing.T) {
	ok, err := IsPackageTrustedLocal(PackageSpec{Name: "opencode", Raw: "opencode"}, []string{"https://127.0.0.1:8443/module/trust"})
	if err != nil || ok {
		t.Fatalf("URL-only must be local-untrusted; ok=%v err=%v", ok, err)
	}
}

func TestEvaluateTrustedModules_URLOnlyQueriesRemote(t *testing.T) {
	var hits int
	prev := evaluateRemoteRequestFn
	evaluateRemoteRequestFn = func(endpoint string, modules []PackageSpec, opts RemoteRequestOptions) RemoteResult {
		hits++
		if endpoint != "https://127.0.0.1:8443/module/trust" {
			t.Errorf("endpoint=%s", endpoint)
		}
		if len(modules) != 1 || modules[0].Name != "opencode" {
			t.Errorf("modules=%#v", modules)
		}
		return RemoteResult{Allowed: false, Status: 403}
	}
	defer func() { evaluateRemoteRequestFn = prev }()

	res := EvaluateTrustedModules(
		[]PackageSpec{{Name: "opencode", Raw: "opencode"}},
		[]string{"https://127.0.0.1:8443/module/trust"},
		RemoteTLSOptions{TimeoutSec: 2},
	)
	if res.Trusted || !res.RemoteQueried || hits != 1 {
		t.Fatalf("want remote 403 untrusted, got %#v hits=%d", res, hits)
	}
}

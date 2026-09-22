package modulefirewall

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEvaluateRemote_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		if got := r.Header.Get("User-Agent"); got != "NVM-Windows-Firewall/1" {
			t.Errorf("User-Agent=%q", got)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "text/plain") {
			t.Errorf("Content-Type=%q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := EvaluateRemote(srv.URL, []PackageSpec{{Raw: "eslint@8.0.0"}}, RemoteTLSOptions{TimeoutSec: 2})
	if !res.Allowed || res.Status != 200 {
		t.Fatalf("res=%+v", res)
	}
}

func TestEvaluateRemote_ForbiddenTSV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "eslint\t2026-01-01\tcve\nlodash\t2026-02-02\tlicense\n")
	}))
	defer srv.Close()

	res := EvaluateRemote(srv.URL, []PackageSpec{{Name: "eslint"}}, RemoteTLSOptions{TimeoutSec: 2})
	if res.Allowed || res.Status != 403 {
		t.Fatalf("res=%+v", res)
	}
	if len(res.Blocks) != 2 {
		t.Fatalf("blocks=%v", res.Blocks)
	}
	if res.Blocks[0].Name != "eslint" || res.Blocks[0].Date != "2026-01-01" || res.Blocks[0].Reason != "cve" {
		t.Fatalf("block0=%+v", res.Blocks[0])
	}
	if res.Blocks[1].Name != "lodash" || res.Blocks[1].Reason != "license" {
		t.Fatalf("block1=%+v", res.Blocks[1])
	}
	if res.ErrorMsg != "" {
		t.Fatalf("403 ErrorMsg=%q, want empty", res.ErrorMsg)
	}
	if got := FormatRemoteUserMessage(res); got != "blocked by remote policy" {
		t.Fatalf("FormatRemoteUserMessage=%q", got)
	}
}

func TestEvaluateRemote_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	res := EvaluateRemote(srv.URL, []PackageSpec{{Raw: "eslint"}}, RemoteTLSOptions{TimeoutSec: 2})
	if res.Allowed || res.Status != 500 {
		t.Fatalf("res=%+v", res)
	}
	if !strings.Contains(res.ErrorMsg, "unexpected HTTP") {
		t.Fatalf("ErrorMsg=%q", res.ErrorMsg)
	}
	if !strings.Contains(FormatRemoteUserMessage(res), "500") {
		t.Fatalf("user message should include status: %q", FormatRemoteUserMessage(res))
	}
}

func TestEvaluateRemote_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := EvaluateRemote(srv.URL, []PackageSpec{{Raw: "eslint"}}, RemoteTLSOptions{TimeoutSec: 1})
	if res.Allowed {
		t.Fatal("expected timeout failure")
	}
	if res.Status != 0 {
		t.Fatalf("Status=%d, want 0", res.Status)
	}
	if res.ErrorMsg == "" {
		t.Fatal("expected ErrorMsg")
	}
}

func TestEvaluateRemote_DefaultTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// TimeoutSec<=0 must default to 3s; short sleep should succeed.
	res := EvaluateRemote(srv.URL, []PackageSpec{{Raw: "eslint"}}, RemoteTLSOptions{TimeoutSec: 0})
	if !res.Allowed || res.Status != 200 {
		t.Fatalf("default timeout failed: %+v", res)
	}
}

func TestEvaluateRemote_POSTBody(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mods := []PackageSpec{
		{Raw: "raw-token"},
		{Name: "eslint", Version: "8.0.0"},
		{Name: "lodash"},
	}
	res := EvaluateRemote(srv.URL, mods, RemoteTLSOptions{TimeoutSec: 2})
	if !res.Allowed {
		t.Fatalf("res=%+v", res)
	}
	wantLines := []string{"raw-token", "eslint@8.0.0", "lodash"}
	got := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(got) != len(wantLines) {
		t.Fatalf("body=%q, want lines %v", body, wantLines)
	}
	for i, want := range wantLines {
		if got[i] != want {
			t.Fatalf("line %d = %q, want %q", i, got[i], want)
		}
	}
}

func TestEvaluateRemote_EmptyTLSPinsNoCrash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Blank org/thumb entries normalize away → no peer verifier; httptest must not crash.
	res := EvaluateRemote(srv.URL, []PackageSpec{{Raw: "eslint"}}, RemoteTLSOptions{
		TimeoutSec:         2,
		AllowedOrgs:        []string{"", " "},
		AllowedThumbprints: []string{"", ":", "  "},
	})
	if !res.Allowed {
		t.Fatalf("empty pins should not break httptest: %+v", res)
	}
}

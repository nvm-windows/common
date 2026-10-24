//go:build windows

package verifycache

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParentIsNvmProxy(t *testing.T) {
	dataRoot := t.TempDir()
	proxy := filepath.Join(dataRoot, "proxy.exe")
	shim := filepath.Join(dataRoot, ".shim")
	if err := os.MkdirAll(shim, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("proxy-bytes")
	if err := os.WriteFile(proxy, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	vue := filepath.Join(shim, "vue.exe")
	if err := os.WriteFile(vue, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	node := filepath.Join(shim, "node.exe")
	if err := os.WriteFile(node, []byte("node-shim"), 0o644); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(shim, "evil.exe")
	if err := os.WriteFile(evil, []byte("not-proxy"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !parentIsNvmProxy(proxy, dataRoot) {
		t.Fatal("canonical proxy.exe must match")
	}
	if !parentIsNvmProxy(vue, dataRoot) {
		t.Fatal(".shim vue.exe with proxy bytes must match")
	}
	if parentIsNvmProxy(node, dataRoot) {
		t.Fatal(".shim node.exe must not match")
	}
	if parentIsNvmProxy(evil, dataRoot) {
		t.Fatal("mismatched .shim exe must not match")
	}
	if parentIsNvmProxy(`C:\Windows\System32\cmd.exe`, dataRoot) {
		t.Fatal("cmd.exe must not match")
	}
	if parentIsNvmProxy("", dataRoot) {
		t.Fatal("empty parent must not match")
	}
}

func TestAuthorizeSignScriptFromParent(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	proxy := filepath.Join(dataRoot, "proxy.exe")
	shim := filepath.Join(dataRoot, ".shim")
	if err := os.MkdirAll(shim, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("proxy-bytes")
	if err := os.WriteFile(proxy, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	vue := filepath.Join(shim, "vue.exe")
	if err := os.WriteFile(vue, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	origParent := parentImagePathFn
	origPID := parentPIDFn
	origPipe := stdinPipeServerPIDFn
	origPub := verifyParentPublisherFn
	t.Cleanup(func() {
		parentImagePathFn = origParent
		parentPIDFn = origPID
		stdinPipeServerPIDFn = origPipe
		verifyParentPublisherFn = origPub
	})

	parentPIDFn = func() uint32 { return 4242 }
	stdinPipeServerPIDFn = func() (uint32, bool) { return 4242, true }
	verifyParentPublisherFn = func(string) error { return nil }
	parentImagePathFn = func() string { return vue }

	if err := AuthorizeSignScriptFromParent(); err != nil {
		t.Fatalf("signed proxy parent + matching pipe: %v", err)
	}

	parentImagePathFn = func() string { return `C:\Windows\System32\cmd.exe` }
	if err := AuthorizeSignScriptFromParent(); err == nil {
		t.Fatal("cmd.exe parent must fail")
	}

	parentImagePathFn = func() string { return vue }
	stdinPipeServerPIDFn = func() (uint32, bool) { return 0, false }
	if err := AuthorizeSignScriptFromParent(); err == nil {
		t.Fatal("console stdin must fail")
	}

	stdinPipeServerPIDFn = func() (uint32, bool) { return 99, true }
	if err := AuthorizeSignScriptFromParent(); err == nil {
		t.Fatal("pipe from another PID must fail")
	}

	stdinPipeServerPIDFn = func() (uint32, bool) { return 4242, true }
	verifyParentPublisherFn = func(string) error { return os.ErrPermission }
	if err := AuthorizeSignScriptFromParent(); err == nil {
		t.Fatal("publisher mismatch must fail")
	}
}

func TestReadSignScriptPath(t *testing.T) {
	got, err := ReadSignScriptPath(strings.NewReader("  C:\\nvm\\installs\\v24\\vue.cmd \n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != `C:\nvm\installs\v24\vue.cmd` {
		t.Fatalf("got %q", got)
	}
	if _, err := ReadSignScriptPath(strings.NewReader("")); err == nil {
		t.Fatal("empty path must fail")
	}
	if _, err := ReadSignScriptPath(strings.NewReader("a\nb")); err == nil {
		t.Fatal("newline in path must fail")
	}
	if _, err := ReadSignScriptPath(bytes.NewReader(bytes.Repeat([]byte("x"), maxSignScriptPathBytes+1))); err == nil {
		t.Fatal("oversize path must fail")
	}
}

func TestIsDelegatedLauncherPath(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	versionDir := filepath.Join(dataRoot, "installs", "v24.0.0")
	ok := filepath.Join(versionDir, "vue.cmd")
	nested := filepath.Join(versionDir, "node_modules", "npm", "bin", "npm-cli.js")
	if !IsDelegatedLauncherPath(ok) {
		t.Fatal("version-dir cmd must pass")
	}
	if !IsDelegatedLauncherPath(nested) {
		t.Fatal("nested js under installs must pass")
	}
	if IsDelegatedLauncherPath(`C:\Temp\evil.cmd`) {
		t.Fatal("temp cmd must fail")
	}
	if IsDelegatedLauncherPath(filepath.Join(versionDir, "vue.exe")) {
		t.Fatal("exe must fail")
	}

	t.Setenv("LOCALAPPDATA", filepath.Join(dataRoot, "Local"))
	yarn := filepath.Join(dataRoot, "Local", "Yarn", "bin", "vue.cmd")
	if !IsDelegatedLauncherPath(yarn) {
		t.Fatal("Yarn Classic bin must pass")
	}
}

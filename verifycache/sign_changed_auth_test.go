//go:build windows

package verifycache

import (
	"path/filepath"
	"testing"
)

func TestSignChangedAuthorizedByShimParent(t *testing.T) {
	shim := `C:\Users\x\AppData\Local\Author Software\nvm\.shim`
	pwsh := `C:\Program Files\PowerShell\7\pwsh.exe`
	npm := filepath.Join(shim, "npm.exe")
	opencode := filepath.Join(shim, "opencode.exe")

	tests := []struct {
		name      string
		parent    string
		ancestors []string
		want      bool
	}{
		{
			name:      "user npm from shell",
			parent:    npm,
			ancestors: []string{npm, pwsh},
			want:      true,
		},
		{
			name:      "nested npm under opencode",
			parent:    npm,
			ancestors: []string{npm, filepath.Join(`C:\nvm\installs\v24\node.exe`), opencode, pwsh},
			want:      false,
		},
		{
			name:      "opencode spawning nvm --reshim",
			parent:    opencode,
			ancestors: []string{opencode, pwsh},
			want:      false,
		},
		{
			name:      "cmd.exe parent",
			parent:    `C:\Windows\System32\cmd.exe`,
			ancestors: []string{`C:\Windows\System32\cmd.exe`},
			want:      false,
		},
		{
			name:      "empty parent",
			parent:    "",
			ancestors: nil,
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := signChangedAuthorizedByShimParent(tt.parent, tt.ancestors, shim)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizeSignChangedFromParentIgnoresEnv(t *testing.T) {
	dataRoot := setupVerifyCacheTestProfile(t)
	shim := filepath.Join(dataRoot, ".shim")
	t.Setenv("NVM_SIGN_CHANGED_MODULES", "1")

	origParent := parentImagePathFn
	origAncestors := ancestorImagePathsFn
	t.Cleanup(func() {
		parentImagePathFn = origParent
		ancestorImagePathsFn = origAncestors
	})

	parentImagePathFn = func() string { return `C:\Windows\System32\cmd.exe` }
	ancestorImagePathsFn = func() []string { return []string{`C:\Windows\System32\cmd.exe`} }
	if AuthorizeSignChangedFromParent() {
		t.Fatal("env + cmd.exe parent must not authorize")
	}

	npm := filepath.Join(shim, "npm.exe")
	parentImagePathFn = func() string { return npm }
	ancestorImagePathsFn = func() []string { return []string{npm, `C:\Windows\System32\cmd.exe`} }
	if !AuthorizeSignChangedFromParent() {
		t.Fatal("user npm parent must authorize")
	}

	opencode := filepath.Join(shim, "opencode.exe")
	parentImagePathFn = func() string { return npm }
	ancestorImagePathsFn = func() []string { return []string{npm, opencode} }
	if AuthorizeSignChangedFromParent() {
		t.Fatal("nested opencode must not authorize")
	}
}

func TestParentIsNvmReshim(t *testing.T) {
	origParent := parentImagePathFn
	origDir := nvmExeDirFn
	t.Cleanup(func() {
		parentImagePathFn = origParent
		nvmExeDirFn = origDir
	})

	dir := t.TempDir()
	nvmExeDirFn = func() string { return dir }
	want := filepath.Join(dir, "utils", "reshim.exe")
	parentImagePathFn = func() string { return want }
	if !ParentIsNvmReshim() {
		t.Fatal("reshim.exe under utils must match")
	}

	parentImagePathFn = func() string { return `C:\Windows\System32\cmd.exe` }
	if ParentIsNvmReshim() {
		t.Fatal("cmd.exe must not match")
	}
}

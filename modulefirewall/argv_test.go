package modulefirewall

import (
	"reflect"
	"testing"
)

func TestInstallLike(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		args []string
		want bool
	}{
		{"npm i", "npm", []string{"i", "eslint"}, true},
		{"npm add", "npm", []string{"add", "eslint"}, true},
		{"npm exec", "npm", []string{"exec", "eslint"}, true},
		{"pnpm dlx", "pnpm", []string{"dlx", "create-react-app"}, true},
		{"yarn create", "yarn", []string{"create", "vite"}, true},
		{"unknown cmd", "cargo", []string{"install", "ripgrep"}, false},
		{"npm list not install", "npm", []string{"list"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InstallLike(tt.cmd, tt.args); got != tt.want {
				t.Fatalf("InstallLike(%q,%v)=%v, want %v", tt.cmd, tt.args, got, tt.want)
			}
		})
	}
}

func TestIsGlobalInstall(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		args []string
		want bool
	}{
		{"-ig", "npm", []string{"install", "-ig", "eslint"}, true},
		{"--global", "npm", []string{"install", "--global", "eslint"}, true},
		{"yarn global", "yarn", []string{"global", "add", "eslint"}, true},
		{"no -g", "npm", []string{"install", "eslint"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsGlobalInstall(tt.cmd, tt.args); got != tt.want {
				t.Fatalf("IsGlobalInstall(%q,%v)=%v, want %v", tt.cmd, tt.args, got, tt.want)
			}
		})
	}
}

func TestExtractPackageArgs(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		args []string
		want []string
	}{
		{
			name: "npm install -g",
			cmd:  "npm",
			args: []string{"install", "-g", "eslint", "porthog"},
			want: []string{"eslint", "porthog"},
		},
		{
			name: "skip --registry VAL",
			cmd:  "npm",
			args: []string{"install", "--registry", "https://registry.npmjs.org", "eslint"},
			want: []string{"eslint"},
		},
		{
			name: "yarn global add",
			cmd:  "yarn",
			args: []string{"global", "add", "eslint"},
			want: []string{"eslint"},
		},
		{
			name: "pnpm exec",
			cmd:  "pnpm",
			args: []string{"exec", "eslint", "--", "fix"},
			want: []string{"eslint", "fix"},
		},
		{
			name: "npx",
			cmd:  "npx",
			args: []string{"-y", "create-vite@latest"},
			want: []string{"create-vite@latest"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs := ExtractPackageArgs(tt.cmd, tt.args)
			got := make([]string, len(pkgs))
			for i, p := range pkgs {
				got[i] = p.Raw
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

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
		{"pnpm flagged dlx", "pnpm", []string{"--package=evil", "dlx", "cowsay"}, true},
		{"yarn create", "yarn", []string{"create", "vite"}, true},
		{"npx", "npx", []string{"-y", "cowsay"}, true},
		{"bunx", "bunx", []string{"cowsay"}, true},
		{"bun install", "bun", []string{"install", "left-pad"}, true},
		{"bun x", "bun", []string{"x", "cowsay"}, true},
		{"bun create", "bun", []string{"create", "vite"}, true},
		{"bun update", "bun", []string{"update"}, true},
		{"bun test passthrough", "bun", []string{"test"}, false},
		{"bun run passthrough", "bun", []string{"run", "dev"}, false},
		{"unknown cmd", "cargo", []string{"install", "ripgrep"}, false},
		{"npm list not install", "npm", []string{"list"}, false},
		{"pnpm run not install", "pnpm", []string{"run", "test"}, false},
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
			want: []string{"eslint"},
		},
		{
			name: "npx",
			cmd:  "npx",
			args: []string{"-y", "create-vite@latest"},
			want: []string{"create-vite@latest"},
		},
		{
			name: "npx extra argv",
			cmd:  "npx",
			args: []string{"cowsay", "hello"},
			want: []string{"cowsay"},
		},
		{
			name: "npx --package=",
			cmd:  "npx",
			args: []string{"--package=evil", "cowsay"},
			want: []string{"evil"},
		},
		{
			name: "npx -p",
			cmd:  "npx",
			args: []string{"-p", "evil", "cowsay", "hi"},
			want: []string{"evil"},
		},
		{
			name: "pnpm dlx",
			cmd:  "pnpm",
			args: []string{"dlx", "create-vite"},
			want: []string{"create-vite"},
		},
		{
			name: "pnpm --package dlx",
			cmd:  "pnpm",
			args: []string{"--package=evil", "dlx", "cowsay"},
			want: []string{"evil"},
		},
		{
			name: "yarn create",
			cmd:  "yarn",
			args: []string{"create", "vite"},
			want: []string{"create-vite"},
		},
		{
			name: "npm exec --package",
			cmd:  "npm",
			args: []string{"exec", "--package=evil", "--", "cowsay"},
			want: []string{"evil"},
		},
		{
			name: "bunx",
			cmd:  "bunx",
			args: []string{"cowsay", "hello"},
			want: []string{"cowsay"},
		},
		{
			name: "bun x",
			cmd:  "bun",
			args: []string{"x", "cowsay"},
			want: []string{"cowsay"},
		},
		{
			name: "bun add",
			cmd:  "bun",
			args: []string{"add", "eslint@9"},
			want: []string{"eslint@9"},
		},
		{
			name: "bun create",
			cmd:  "bun",
			args: []string{"create", "vite"},
			want: []string{"create-vite"},
		},
		{
			name: "bun --cwd add",
			cmd:  "bun",
			args: []string{"--cwd", `C:\tmp`, "add", "left-pad"},
			want: []string{"left-pad"},
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

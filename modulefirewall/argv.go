package modulefirewall

import (
	"strings"
)

// InstallLike reports whether PM args look like an install/add/npx execution.
func InstallLike(command string, args []string) bool {
	cmd := strings.ToLower(strings.TrimSpace(command))
	switch cmd {
	case "npx":
		return true
	case "npm":
		return npmInstallLike(args)
	case "pnpm", "vlt":
		return pnpmInstallLike(args)
	case "yarn":
		return yarnInstallLike(args)
	default:
		return false
	}
}

// IsGlobalInstall reports -g/--global or yarn global.
func IsGlobalInstall(command string, args []string) bool {
	cmd := strings.ToLower(strings.TrimSpace(command))
	if cmd == "yarn" {
		if len(args) > 0 && strings.EqualFold(args[0], "global") {
			return true
		}
	}
	for _, arg := range args {
		if arg == "--global" {
			return true
		}
		if len(arg) >= 2 && arg[0] == '-' && arg[1] != '-' {
			for _, ch := range arg[1:] {
				if ch == 'g' {
					return true
				}
			}
		}
	}
	return false
}

// ExtractPackageArgs returns package tokens from install-like argv (best-effort).
func ExtractPackageArgs(command string, args []string) []PackageSpec {
	cmd := strings.ToLower(strings.TrimSpace(command))
	var tokens []string
	switch cmd {
	case "npx":
		tokens = npxPackages(args)
	case "npm":
		tokens = npmPackages(args)
	case "pnpm", "vlt":
		tokens = pnpmPackages(args)
	case "yarn":
		tokens = yarnPackages(args)
	}
	out := make([]PackageSpec, 0, len(tokens))
	for _, t := range tokens {
		spec, err := ParsePackageToken(t)
		if err != nil {
			continue
		}
		out = append(out, spec)
	}
	return out
}

func npmInstallLike(args []string) bool {
	if len(args) == 0 {
		return false
	}
	sub := strings.ToLower(args[0])
	switch sub {
	case "install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isntal", "isntall", "ci":
		return true
	case "exec":
		return true
	default:
		return false
	}
}

func pnpmInstallLike(args []string) bool {
	if len(args) == 0 {
		return false
	}
	sub := strings.ToLower(args[0])
	switch sub {
	case "install", "i", "add", "exec", "dlx", "ci":
		return true
	default:
		return false
	}
}

func yarnInstallLike(args []string) bool {
	if len(args) == 0 {
		return true // yarn with no args installs from package.json — no explicit pkgs
	}
	sub := strings.ToLower(args[0])
	switch sub {
	case "add", "install", "global", "dlx", "create":
		return true
	default:
		return false
	}
}

func skipFlag(arg string) bool {
	return strings.HasPrefix(arg, "-")
}

func npmPackages(args []string) []string {
	if !npmInstallLike(args) {
		return nil
	}
	start := 1
	if len(args) > 0 && strings.EqualFold(args[0], "exec") {
		start = 1
	}
	return collectPositional(args[start:])
}

func pnpmPackages(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	sub := strings.ToLower(args[0])
	if sub == "dlx" || sub == "exec" {
		return collectPositional(args[1:])
	}
	if sub == "add" || sub == "install" || sub == "i" {
		return collectPositional(args[1:])
	}
	return nil
}

func yarnPackages(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	i := 0
	if strings.EqualFold(args[0], "global") {
		i = 1
		if i >= len(args) {
			return nil
		}
	}
	sub := strings.ToLower(args[i])
	switch sub {
	case "add", "install":
		return collectPositional(args[i+1:])
	case "dlx", "create":
		return collectPositional(args[i+1:])
	default:
		return nil
	}
}

func npxPackages(args []string) []string {
	return collectPositional(args)
}

func collectPositional(args []string) []string {
	var out []string
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if skipFlag(arg) {
			// flags that take values
			switch arg {
			case "--prefix", "--workspace", "-w", "--omit", "--include", "--tag", "--registry":
				skipNext = true
			}
			continue
		}
		out = append(out, arg)
	}
	return out
}

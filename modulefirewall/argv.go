package modulefirewall

import (
	"strings"
)

// InstallLike reports whether PM args look like an install/add/npx execution.
func InstallLike(command string, args []string) bool {
	cmd := strings.ToLower(strings.TrimSpace(command))
	switch cmd {
	case "npx", "bunx":
		return true
	case "npm":
		return npmInstallLike(args)
	case "pnpm", "vlt":
		return pnpmInstallLike(args)
	case "yarn", "yarnpkg":
		return yarnInstallLike(args)
	case "bun":
		return bunInstallLike(args)
	default:
		return false
	}
}

// IsGlobalInstall reports -g/--global or yarn global.
func IsGlobalInstall(command string, args []string) bool {
	cmd := strings.ToLower(strings.TrimSpace(command))
	if cmd == "yarn" || cmd == "yarnpkg" {
		if sub, _ := firstSubcommand(args); strings.EqualFold(sub, "global") {
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
	tokens := collectPackages(cmd, args)
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
	sub, _ := firstSubcommand(args)
	switch sub {
	case "install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isntal", "isntall",
		"exec", "ci", "create", "init":
		return true
	default:
		return false
	}
}

func pnpmInstallLike(args []string) bool {
	sub, _ := firstSubcommand(args)
	switch sub {
	case "install", "i", "add", "exec", "dlx", "ci", "create":
		return true
	default:
		return false
	}
}

func yarnInstallLike(args []string) bool {
	if len(args) == 0 {
		return true
	}
	sub, _ := firstSubcommand(args)
	if sub == "" {
		return false
	}
	switch sub {
	case "add", "install", "global", "dlx", "create", "ci":
		return true
	default:
		return false
	}
}

func bunInstallLike(args []string) bool {
	sub, _ := firstSubcommand(args)
	switch sub {
	case "install", "i", "add", "x", "create", "update":
		return true
	default:
		return false
	}
}

func skipFlag(arg string) bool {
	return strings.HasPrefix(arg, "-")
}

func packageFlagValue(arg string) (value string, isPkg bool, needsNext bool) {
	if arg == "-p" || strings.EqualFold(arg, "--package") {
		return "", true, true
	}
	if strings.HasPrefix(strings.ToLower(arg), "--package=") {
		return arg[len("--package="):], true, false
	}
	if strings.HasPrefix(arg, "-p=") {
		return arg[len("-p="):], true, false
	}
	return "", false, false
}

func flagTakesValue(arg string) bool {
	switch arg {
	case "--prefix", "--workspace", "-w", "--omit", "--include", "--tag", "--registry",
		"-c", "--call", "--shell", "--filter", "--dir", "--folder", "-C",
		"--cwd", "--config":
		return true
	default:
		return false
	}
}

func firstSubcommand(args []string) (string, int) {
	skipNext := false
	for i, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--" {
			return "", -1
		}
		if _, isPkg, needsNext := packageFlagValue(arg); isPkg {
			if needsNext {
				skipNext = true
			}
			continue
		}
		if skipFlag(arg) {
			if flagTakesValue(arg) {
				skipNext = true
			}
			continue
		}
		return strings.ToLower(arg), i
	}
	return "", -1
}

func isExecLike(cmd, sub string) bool {
	switch cmd {
	case "npx", "bunx":
		return true
	case "npm":
		return sub == "exec" || sub == "create" || sub == "init"
	case "pnpm", "vlt":
		return sub == "exec" || sub == "dlx" || sub == "create"
	case "yarn", "yarnpkg":
		return sub == "dlx" || sub == "create"
	case "bun":
		return sub == "x" || sub == "create"
	default:
		return false
	}
}

func mapCreateStarter(starter string) string {
	name, ver := splitNameVersion(starter)
	mapped := name
	if strings.HasPrefix(name, "@") {
		if slash := strings.LastIndex(name, "/"); slash >= 0 {
			pkg := name[slash+1:]
			if !strings.HasPrefix(pkg, "create-") {
				mapped = name[:slash] + "/create-" + pkg
			}
		}
	} else if !strings.HasPrefix(name, "create-") {
		mapped = "create-" + name
	}
	if ver == "" {
		return mapped
	}
	return mapped + "@" + ver
}

func collectPackages(cmd string, args []string) []string {
	var fromFlags []string
	var positionals []string
	skipNext := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--" {
			break
		}
		if value, isPkg, needsNext := packageFlagValue(arg); isPkg {
			if needsNext {
				if i+1 < len(args) {
					fromFlags = append(fromFlags, args[i+1])
					skipNext = true
				}
			} else if value != "" {
				fromFlags = append(fromFlags, value)
			}
			continue
		}
		if skipFlag(arg) {
			if flagTakesValue(arg) {
				skipNext = true
			}
			continue
		}
		positionals = append(positionals, arg)
	}

	sub := ""
	rest := positionals
	if cmd != "npx" && cmd != "bunx" && len(rest) > 0 {
		sub = strings.ToLower(rest[0])
		rest = rest[1:]
		if (cmd == "yarn" || cmd == "yarnpkg") && sub == "global" && len(rest) > 0 {
			sub = strings.ToLower(rest[0])
			rest = rest[1:]
		}
	}

	if isExecLike(cmd, sub) {
		if len(fromFlags) > 0 {
			return fromFlags
		}
		if len(rest) == 0 {
			return nil
		}
		first := rest[0]
		if sub == "create" || sub == "init" {
			first = mapCreateStarter(first)
		}
		return []string{first}
	}
	out := make([]string, 0, len(fromFlags)+len(rest))
	out = append(out, fromFlags...)
	out = append(out, rest...)
	return out
}

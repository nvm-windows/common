package modulefirewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManifestArtifact is the HTTPS POST payload for install-policy remotes.
type ManifestArtifact struct {
	Body            []byte
	ContentType     string
	PackageShasum   string // x-nvm-package-shasum when Body is package.json
	Modules         []PackageSpec
	Source          string // "lock" | "package.json" | "cli"
	ProjectDir      string
	PackageJSONPath string
	LockPath        string
}

// CollectOptions controls project manifest / lock collection.
type CollectOptions struct {
	Cwd            string
	Command        string // shim: npm, npx, pnpm, yarn, vlt
	Args           []string
	SkipLockfile   bool
	IncludeDevDeps bool // ignored when productionOmit(Args); force true/false via DetectIncludeDev
}

// DetectIncludeDev returns whether package.json should include devDependencies.
func DetectIncludeDev(args []string) bool {
	return !productionOmit(args)
}

func productionOmit(args []string) bool {
	for _, a := range args {
		lower := strings.ToLower(strings.TrimSpace(a))
		if lower == "--production" || lower == "-p" || lower == "--only=production" {
			return true
		}
		if strings.HasPrefix(lower, "--omit=") {
			omit := strings.TrimPrefix(lower, "--omit=")
			for _, part := range strings.Split(omit, ",") {
				if strings.TrimSpace(part) == "dev" {
					return true
				}
			}
		}
	}
	return false
}

// ManifestExpandable reports whether empty CLI packages should expand from package.json/lock.
func ManifestExpandable(command string, args []string) bool {
	cmd := strings.ToLower(strings.TrimSpace(command))
	switch cmd {
	case "npx":
		return false
	case "npm":
		if len(args) == 0 {
			return false
		}
		sub := strings.ToLower(args[0])
		switch sub {
		case "install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isntal", "isntall", "ci":
			return true
		case "exec":
			return false
		default:
			return false
		}
	case "pnpm", "vlt":
		if len(args) == 0 {
			return false
		}
		sub := strings.ToLower(args[0])
		switch sub {
		case "install", "i", "add", "ci":
			return true
		default:
			return false
		}
	case "yarn":
		if len(args) == 0 {
			return true
		}
		sub := strings.ToLower(args[0])
		switch sub {
		case "install", "add", "ci":
			return true
		case "global", "dlx", "create":
			return false
		default:
			return false
		}
	default:
		return false
	}
}

// CollectInstallPackages returns CLI packages, or expands from lock/package.json when empty.
func CollectInstallPackages(opts CollectOptions) ([]PackageSpec, error) {
	cli := ExtractPackageArgs(opts.Command, opts.Args)
	if len(cli) > 0 {
		return cli, nil
	}
	if !ManifestExpandable(opts.Command, opts.Args) {
		return nil, nil
	}
	art, err := BuildManifestArtifact(opts)
	if err != nil {
		return nil, err
	}
	return art.Modules, nil
}

// BuildManifestArtifact resolves project files and builds remote body + module list.
func BuildManifestArtifact(opts CollectOptions) (ManifestArtifact, error) {
	cwd := strings.TrimSpace(opts.Cwd)
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return ManifestArtifact{}, err
		}
	}
	cwd, err := filepath.Abs(cwd)
	if err != nil {
		return ManifestArtifact{}, err
	}

	pkgPath, err := findNearestFile(cwd, "package.json")
	if err != nil || pkgPath == "" {
		return ManifestArtifact{Source: "cli", ProjectDir: cwd}, nil
	}
	projectDir := filepath.Dir(pkgPath)

	includeDev := DetectIncludeDev(opts.Args)
	if !opts.SkipLockfile {
		for _, name := range LockfileCandidates(opts.Command) {
			lockPath := filepath.Join(projectDir, name)
			if st, err := os.Stat(lockPath); err == nil && !st.IsDir() {
				mods, err := ParseLockFilePackages(lockPath)
				if err == nil && len(mods) > 0 {
					return ManifestArtifact{
						Body:            modulesBody(mods),
						ContentType:     "text/plain; charset=utf-8",
						Modules:         mods,
						Source:          "lock",
						ProjectDir:      projectDir,
						PackageJSONPath: pkgPath,
						LockPath:        lockPath,
					}, nil
				}
			}
		}
	}

	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		return ManifestArtifact{}, err
	}
	mods, err := ParsePackageJSONDirectDeps(raw, includeDev)
	if err != nil {
		return ManifestArtifact{}, err
	}
	sum := sha256.Sum256(raw)
	return ManifestArtifact{
		Body:            raw,
		ContentType:     "application/json",
		PackageShasum:   hex.EncodeToString(sum[:]),
		Modules:         mods,
		Source:          "package.json",
		ProjectDir:      projectDir,
		PackageJSONPath: pkgPath,
	}, nil
}

func modulesBody(mods []PackageSpec) []byte {
	var b strings.Builder
	for _, m := range mods {
		line := m.Raw
		if line == "" {
			line = m.Name
			if m.Version != "" {
				line = m.Name + "@" + m.Version
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func findNearestFile(startDir, name string) (string, error) {
	dir := startDir
	for {
		candidate := filepath.Join(dir, name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

// ParsePackageJSONDirectDeps collects direct dependency specs from package.json bytes.
func ParsePackageJSONDirectDeps(content []byte, includeDev bool) ([]PackageSpec, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("package.json: %w", err)
	}
	sections := []string{"dependencies", "optionalDependencies"}
	if includeDev {
		sections = append(sections, "devDependencies")
	}
	seen := make(map[string]struct{})
	var out []PackageSpec
	for _, sec := range sections {
		raw, ok := root[sec]
		if !ok || len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var deps map[string]json.RawMessage
		if err := json.Unmarshal(raw, &deps); err != nil {
			continue
		}
		for name, verRaw := range deps {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			var ver string
			if err := json.Unmarshal(verRaw, &ver); err != nil {
				continue
			}
			ver = strings.TrimSpace(ver)
			key := strings.ToLower(name)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			rawTok := name
			if ver != "" {
				rawTok = name + "@" + ver
			}
			out = append(out, PackageSpec{Name: name, Version: ver, Raw: rawTok})
		}
	}
	return out, nil
}

// ParseLockPackages extracts package identities from npm lockfile v2/v3 packages map.
func ParseLockPackages(lockPath string) ([]PackageSpec, error) {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	var root struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("lockfile: %w", err)
	}

	seen := make(map[string]struct{})
	var out []PackageSpec

	add := func(name, ver string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		rawTok := name
		if ver != "" {
			rawTok = name + "@" + ver
		}
		out = append(out, PackageSpec{Name: name, Version: ver, Raw: rawTok})
	}

	if len(root.Packages) > 0 {
		for key, meta := range root.Packages {
			if key == "" {
				continue
			}
			name := meta.Name
			if name == "" {
				name = lockPackageNameFromKey(key)
			}
			add(name, meta.Version)
		}
		return out, nil
	}

	// lockfileVersion 1
	for name, meta := range root.Dependencies {
		add(name, meta.Version)
	}
	return out, nil
}

func lockPackageNameFromKey(key string) string {
	key = strings.ReplaceAll(key, "\\", "/")
	const prefix = "node_modules/"
	for {
		idx := strings.LastIndex(key, prefix)
		if idx < 0 {
			break
		}
		key = key[idx+len(prefix):]
	}
	return strings.Trim(key, "/")
}

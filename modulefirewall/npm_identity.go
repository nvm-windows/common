package modulefirewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// NpmIdentitySnapshot is a local, airgap-safe view of npm login state.
// Authenticated means a credential is present in npmrc — not that the registry
// validated the session. Never stores tokens or passwords.
type NpmIdentitySnapshot struct {
	Authenticated bool   `json:"authenticated"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	CredFP        string `json:"cred_fp,omitempty"` // sha256 of primary auth material
	UpdatedUnix   int64  `json:"updated"`
	Source        string `json:"source,omitempty"`
}

// RefreshNpmIdentity parses npmrc, updates the on-disk identity cache, and returns
// the snapshot used for firewall JWTs. Safe for airgapped hosts (no network).
func RefreshNpmIdentity(cwd, installRoot, nodeVersion string) NpmIdentitySnapshot {
	deadline := time.Now().Add(contextBudget)
	raw := map[string]any{}
	paths := npmrcCandidatePaths(cwd, installRoot, nodeVersion)
	for i := len(paths) - 1; i >= 0; i-- {
		if !budgetOK(deadline) {
			break
		}
		b, err := os.ReadFile(paths[i])
		if err != nil {
			continue
		}
		mergeNpmrcMap(raw, string(b))
	}

	auth := npmCredentialPresent(raw)
	credKey, fp := npmCredentialFingerprint(raw)
	prev := loadNpmIdentityCache()

	snap := NpmIdentitySnapshot{
		Authenticated: auth,
		UpdatedUnix:   time.Now().Unix(),
	}
	if !auth {
		storeNpmIdentityCache(snap)
		return snap
	}

	name, email, source := identityForCredentialHost(raw, credKey)
	if name == "" && prev.Name != "" && prev.CredFP != "" && prev.CredFP == fp {
		// Same credential fingerprint: keep last known username from a prior capture.
		name = prev.Name
		if email == "" {
			email = prev.Email
		}
		source = "npm-identity-cache"
	}
	snap.Name = name
	snap.Email = email
	snap.CredFP = fp
	snap.Source = source
	if snap.Source == "" && (name != "" || email != "") {
		snap.Source = "npmrc-login"
	}
	storeNpmIdentityCache(snap)
	return snap
}

// CaptureNpmIdentity refreshes from npmrc, then if authenticated but username
// unknown runs `npm whoami` once (login/whoami path only — not install hot path).
func CaptureNpmIdentity(cwd, installRoot, nodeVersion string) NpmIdentitySnapshot {
	snap := RefreshNpmIdentity(cwd, installRoot, nodeVersion)
	if !snap.Authenticated || strings.TrimSpace(snap.Name) != "" {
		return snap
	}
	if u := npmWhoamiOnce(cwd, installRoot, nodeVersion); u != "" {
		snap.Name = u
		snap.Source = "npm-whoami"
		snap.UpdatedUnix = time.Now().Unix()
		storeNpmIdentityCache(snap)
	}
	return snap
}

const npmWhoamiCaptureTimeout = 3 * time.Second

func npmWhoamiOnce(cwd, installRoot, nodeVersion string) string {
	nodeBin, npmCLI := findNodeAndNpmCLI(installRoot, nodeVersion)
	if nodeBin == "" || npmCLI == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), npmWhoamiCaptureTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nodeBin, npmCLI, "whoami")
	if cwd != "" {
		cmd.Dir = cwd
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	// Warnings may appear on stdout in some environments; take the last non-empty line.
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		name := strings.TrimSpace(lines[i])
		if name == "" {
			continue
		}
		if strings.ContainsAny(name, " \t") {
			continue
		}
		low := strings.ToLower(name)
		if strings.HasPrefix(low, "npm ") || strings.Contains(low, "error") {
			continue
		}
		return name
	}
	return ""
}

func findNodeAndNpmCLI(installRoot, nodeVersion string) (nodeBin, npmCLI string) {
	root := strings.TrimSpace(installRoot)
	ver := strings.TrimPrefix(strings.TrimSpace(nodeVersion), "v")
	if root == "" || ver == "" {
		return "", ""
	}
	nodeName := "node"
	if runtime.GOOS == "windows" {
		nodeName = "node.exe"
	}
	for _, dir := range []string{
		filepath.Join(root, "v"+ver),
		filepath.Join(root, ver),
	} {
		nb := filepath.Join(dir, nodeName)
		cli := filepath.Join(dir, "node_modules", "npm", "bin", "npm-cli.js")
		if st, err := os.Stat(nb); err != nil || st.IsDir() {
			continue
		}
		if st, err := os.Stat(cli); err != nil || st.IsDir() {
			continue
		}
		return nb, cli
	}
	return "", ""
}

// LoadNpmIdentityCache returns the last stored snapshot (may be stale).
func LoadNpmIdentityCache() NpmIdentitySnapshot {
	return loadNpmIdentityCache()
}

// ClearNpmIdentityCache removes the on-disk identity snapshot.
func ClearNpmIdentityCache() {
	_ = os.Remove(npmIdentityCachePath())
}

func identityFromLogin(login any) (name, email, source string) {
	m, ok := login.(map[string]any)
	if !ok || len(m) == 0 {
		return "", "", ""
	}
	if s, _ := m["name"].(string); strings.TrimSpace(s) != "" {
		name = strings.TrimSpace(s)
	}
	if s, _ := m["email"].(string); strings.TrimSpace(s) != "" {
		email = strings.TrimSpace(s)
	}
	if s, _ := m["source"].(string); strings.TrimSpace(s) != "" {
		source = strings.TrimSpace(s)
	}
	return name, email, source
}

// identityForCredentialHost prefers :username/:email on the same registry host as the
// primary auth token so a project .npmrc cannot bind a stray username to the user token.
func identityForCredentialHost(m map[string]any, credKey string) (name, email, source string) {
	prefix := registryHostPrefix(credKey)
	if prefix != "" {
		if s := stringVal(m, prefix+":username"); s != "" {
			name = s
		}
		if s := stringVal(m, prefix+":email"); s != "" {
			email = s
		}
	}
	if name == "" {
		if s := stringVal(m, "username"); s != "" {
			name = s
		}
	}
	if name == "" && (credKey == "_auth" || strings.HasSuffix(strings.ToLower(credKey), ":_auth")) {
		if s, ok := m[credKey].(string); ok {
			if u := decodeBasicAuthUser(s); u != "" {
				name = u
			}
		}
	}
	if name == "" || email == "" {
		if credKey == "_authToken" || strings.HasSuffix(strings.ToLower(credKey), ":_authtoken") {
			if s, ok := m[credKey].(string); ok {
				tmp := map[string]any{}
				applyJWTIdentityClaims(tmp, s)
				if name == "" {
					if u, _ := tmp["name"].(string); u != "" {
						name = u
					}
				}
				if email == "" {
					if e, _ := tmp["email"].(string); e != "" {
						email = e
					}
				}
			}
		}
	}
	if name == "" && email == "" {
		return "", "", ""
	}
	return name, email, "npmrc-login"
}

func stringVal(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func registryHostPrefix(authKey string) string {
	authKey = strings.TrimSpace(authKey)
	for _, suf := range []string{":_authToken", ":_authtoken", ":_auth", ":_password"} {
		if len(authKey) > len(suf) && strings.HasSuffix(strings.ToLower(authKey), strings.ToLower(suf)) {
			// Keep trailing slash form: //host/ → username key //host/:username
			return authKey[:len(authKey)-len(suf)]
		}
	}
	return ""
}

func profileFromSnapshot(snap NpmIdentitySnapshot) any {
	if snap.Name == "" && snap.Email == "" {
		return nil
	}
	p := map[string]any{}
	if snap.Name != "" {
		p["name"] = snap.Name
	}
	if snap.Email != "" {
		p["email"] = snap.Email
	}
	if snap.Source != "" {
		p["source"] = snap.Source
	} else {
		p["source"] = "npm-identity-cache"
	}
	return p
}

func npmCredentialPresent(m map[string]any) bool {
	for k, v := range m {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			continue
		}
		lk := strings.ToLower(k)
		if lk == "_auth" || lk == "_authtoken" ||
			strings.HasSuffix(lk, ":_auth") || strings.HasSuffix(lk, ":_authtoken") {
			return true
		}
	}
	return false
}

// npmCredentialFingerprint returns the chosen auth key and sha256(key+"\n"+value).
func npmCredentialFingerprint(m map[string]any) (credKey, fp string) {
	type kv struct{ key, val string }
	var tokens, basic []kv
	for k, v := range m {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			continue
		}
		lk := strings.ToLower(k)
		switch {
		case lk == "_authtoken" || strings.HasSuffix(lk, ":_authtoken"):
			tokens = append(tokens, kv{k, strings.TrimSpace(s)})
		case lk == "_auth" || strings.HasSuffix(lk, ":_auth"):
			basic = append(basic, kv{k, strings.TrimSpace(s)})
		}
	}
	pick := func(list []kv) kv {
		best := list[0]
		for _, item := range list[1:] {
			if item.key < best.key {
				best = item
			}
		}
		return best
	}
	var chosen kv
	switch {
	case len(tokens) > 0:
		chosen = pick(tokens)
	case len(basic) > 0:
		chosen = pick(basic)
	default:
		return "", ""
	}
	sum := sha256.Sum256([]byte(chosen.key + "\n" + chosen.val))
	return chosen.key, hex.EncodeToString(sum[:])
}

func npmIdentityCachePath() string {
	if base := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); base != "" {
		return filepath.Join(base, "Author Software", "nvm", ".cache", "npm-identity.json")
	}
	if base, err := os.UserCacheDir(); err == nil && strings.TrimSpace(base) != "" {
		return filepath.Join(base, "Author Software", "nvm", "npm-identity.json")
	}
	return filepath.Join(os.TempDir(), "nvm-npm-identity.json")
}

func loadNpmIdentityCache() NpmIdentitySnapshot {
	raw, err := os.ReadFile(npmIdentityCachePath())
	if err != nil {
		return NpmIdentitySnapshot{}
	}
	var snap NpmIdentitySnapshot
	if json.Unmarshal(raw, &snap) != nil {
		return NpmIdentitySnapshot{}
	}
	return snap
}

func storeNpmIdentityCache(snap NpmIdentitySnapshot) {
	path := npmIdentityCachePath()
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	raw, err := json.Marshal(snap)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

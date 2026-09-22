package modulefirewall

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// RequestContext is shared firewall JWT / audit context for allow + trust remotes.
type RequestContext struct {
	Shim          string
	Pwd           string
	NodeVersion   any    // string or nil
	PMFamily      string // "npm" | "pnpm" | "yarn" | ""
	User          string // npm username when known; empty → JWT user null
	Config        any    // object or nil
	Authenticated bool   // local npmrc credential present (airgap-safe; not registry-validated)
}

// contextBudget is the soft ceiling for native profile/config reads.
const contextBudget = 50 * time.Millisecond

// BuildRequestContext gathers shim/pwd/node + optional PM profile/config (null on miss/budget).
func BuildRequestContext(cwd, shim, nodeVersion string) RequestContext {
	return BuildRequestContextWithRoot(cwd, shim, nodeVersion, "")
}

// BuildRequestContextWithRoot is BuildRequestContext plus optional Node install root
// (NVM InstallRoot) so built-in npmrc under the active Node tree is readable.
func BuildRequestContextWithRoot(cwd, shim, nodeVersion, installRoot string) RequestContext {
	shim = strings.ToLower(strings.TrimSpace(shim))
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if abs, err := filepath.Abs(cwd); err == nil {
		cwd = abs
	}

	ctx := RequestContext{
		Shim: shim,
		Pwd:  cwd,
	}
	nv := strings.TrimSpace(nodeVersion)
	if nv == "" {
		ctx.NodeVersion = nil
	} else {
		ctx.NodeVersion = strings.TrimPrefix(nv, "v")
		nv = strings.TrimPrefix(nv, "v")
	}

	deadline := time.Now().Add(contextBudget)
	switch family := shimFamily(shim); family {
	case "npm":
		ctx.PMFamily = "npm"
		cfg, _ := readNpmConfigNative(cwd, installRoot, nv, deadline)
		ctx.Config = cfg
		snap := CaptureNpmIdentity(cwd, installRoot, nv)
		ctx.Authenticated = snap.Authenticated
		ctx.User = strings.TrimSpace(snap.Name)
	case "pnpm":
		ctx.PMFamily = "pnpm"
		cfg, _ := readPnpmConfigNative(cwd, deadline)
		ctx.Config = cfg
		snap := CaptureNpmIdentity(cwd, installRoot, nv)
		ctx.Authenticated = snap.Authenticated
		ctx.User = strings.TrimSpace(snap.Name)
	case "yarn":
		ctx.PMFamily = "yarn"
		cfg := readYarnConfigNative(cwd, deadline)
		ctx.Config = cfg
	}
	return ctx
}

// PackageManagerClaim builds { "user", "config", "authenticated"? } for the active PM family.
func (c RequestContext) PackageManagerClaim() (key string, value map[string]any) {
	if c.PMFamily == "" {
		return "", nil
	}
	var user any
	if strings.TrimSpace(c.User) != "" {
		user = strings.TrimSpace(c.User)
	}
	m := map[string]any{
		"user":   user,
		"config": c.Config,
	}
	switch c.PMFamily {
	case "npm", "pnpm":
		m["authenticated"] = c.Authenticated
	}
	return c.PMFamily, m
}

func shimFamily(shim string) string {
	switch shim {
	case "npm", "npx":
		return "npm"
	case "pnpm", "vlt":
		return "pnpm"
	case "yarn", "yarnpkg":
		return "yarn"
	default:
		return ""
	}
}

func budgetOK(deadline time.Time) bool {
	return time.Now().Before(deadline)
}

func readNpmConfigNative(cwd, installRoot, nodeVersion string, deadline time.Time) (cfg any, login any) {
	if !budgetOK(deadline) {
		return nil, nil
	}
	out := map[string]any{}
	paths := npmrcCandidatePaths(cwd, installRoot, nodeVersion)
	for i := len(paths) - 1; i >= 0; i-- {
		if !budgetOK(deadline) {
			break
		}
		raw, err := os.ReadFile(paths[i])
		if err != nil {
			continue
		}
		mergeNpmrcMap(out, string(raw))
	}
	if len(out) == 0 {
		return nil, nil
	}
	login = npmLoginIdentityFromNpmrc(out)
	scrubAuthKeys(out)
	if len(out) == 0 {
		return nil, login
	}
	return out, login
}

func npmrcCandidatePaths(cwd, installRoot, nodeVersion string) []string {
	var paths []string
	if installRoot != "" && nodeVersion != "" {
		root := strings.TrimSpace(installRoot)
		ver := strings.TrimPrefix(strings.TrimSpace(nodeVersion), "v")
		for _, dir := range []string{
			filepath.Join(root, "v"+ver),
			filepath.Join(root, ver),
		} {
			paths = append(paths,
				filepath.Join(dir, "etc", "npmrc"),
				filepath.Join(dir, "node_modules", "npm", "npmrc"),
			)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".npmrc"))
		if runtime.GOOS == "windows" {
			if appdata := strings.TrimSpace(os.Getenv("APPDATA")); appdata != "" {
				paths = append(paths, filepath.Join(appdata, "npm", "npmrc"))
				paths = append(paths, filepath.Join(appdata, "npm", "etc", "npmrc"))
			}
		} else {
			paths = append(paths, filepath.Join(home, ".config", "npm", "npmrc"))
		}
	}
	if cwd != "" {
		paths = append(paths, filepath.Join(cwd, ".npmrc"))
	}
	return paths
}

// npmProfileFromConfig builds a profile-shaped object from local npmrc identity fields.
// Returns nil when npmrc has no identity fields (no desktop username fill).
func npmProfileFromConfig(cfg any) any {
	profile := map[string]any{}
	m, ok := cfg.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	pick := func(keys ...string) {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					profile[profileKey(k)] = strings.TrimSpace(s)
					return
				}
			}
		}
	}
	pick("name", "init-author-name", "init.author.name")
	pick("email", "init-author-email", "init.author.email")
	pick("url", "init-author-url", "init.author.url", "homepage")
	if len(profile) == 0 {
		return nil
	}
	profile["source"] = "npmrc"
	return profile
}

// npmLoginIdentityFromNpmrc extracts offline login identity from a pre-scrub npmrc map.
// Source is always "npmrc-login". Never keeps passwords or raw tokens.
func npmLoginIdentityFromNpmrc(m map[string]any) any {
	if len(m) == 0 {
		return nil
	}
	profile := map[string]any{}
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		switch {
		case k == "username" || strings.HasSuffix(k, ":username"):
			if profileStringEmpty(profile, "name") {
				profile["name"] = s
			}
		case strings.HasSuffix(k, ":email"):
			if profileStringEmpty(profile, "email") {
				profile["email"] = s
			}
		case k == "_auth" || strings.HasSuffix(k, ":_auth"):
			if user := decodeBasicAuthUser(s); user != "" && profileStringEmpty(profile, "name") {
				profile["name"] = user
			}
		case k == "_authToken" || strings.HasSuffix(k, ":_authToken"):
			applyJWTIdentityClaims(profile, s)
		}
	}
	if len(profile) == 0 {
		return nil
	}
	profile["source"] = "npmrc-login"
	return profile
}

func profileStringEmpty(m map[string]any, key string) bool {
	s, _ := m[key].(string)
	return strings.TrimSpace(s) == ""
}

func decodeBasicAuthUser(encoded string) string {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return ""
		}
	}
	pair := string(raw)
	user, _, ok := strings.Cut(pair, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(user)
}

func applyJWTIdentityClaims(profile map[string]any, token string) {
	if strings.HasPrefix(token, "npm_") {
		return
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return
		}
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil || len(claims) == 0 {
		return
	}
	if profileStringEmpty(profile, "name") {
		for _, key := range []string{"preferred_username", "name"} {
			if s := claimString(claims, key); s != "" {
				profile["name"] = s
				break
			}
		}
	}
	if profileStringEmpty(profile, "email") {
		if s := claimString(claims, "email"); s != "" {
			profile["email"] = s
		}
	}
	if profileStringEmpty(profile, "name") {
		if sub := claimString(claims, "sub"); sub != "" && !strings.ContainsAny(sub, " \t") && !looksLikeUUID(sub) {
			profile["name"] = sub
		}
	}
}

func claimString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

// mergeNpmProfiles fills empty fields in base from overlay. Prefer base values.
// When name is taken from overlay, adopt overlay source.
func mergeNpmProfiles(base, overlay any) any {
	om, _ := overlay.(map[string]any)
	bm, _ := base.(map[string]any)
	if len(om) == 0 {
		return base
	}
	if len(bm) == 0 {
		return cloneProfileMap(om)
	}
	out := cloneProfileMap(bm)
	baseNameEmpty := profileStringEmpty(bm, "name")
	for k, v := range om {
		if k == "source" {
			continue
		}
		if profileStringEmpty(out, k) {
			out[k] = v
		}
	}
	if baseNameEmpty && !profileStringEmpty(out, "name") {
		if src, _ := om["source"].(string); strings.TrimSpace(src) != "" {
			out["source"] = src
		}
	}
	return out
}

func cloneProfileMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func profileKey(k string) string {
	switch k {
	case "init-author-name", "init.author.name":
		return "name"
	case "init-author-email", "init.author.email":
		return "email"
	case "init-author-url", "init.author.url", "homepage":
		return "url"
	default:
		return k
	}
}

func readPnpmConfigNative(cwd string, deadline time.Time) (cfg any, login any) {
	if !budgetOK(deadline) {
		return nil, nil
	}
	out := map[string]any{}
	candidates := []string{
		filepath.Join(cwd, ".npmrc"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".npmrc"),
			filepath.Join(home, "AppData", "Local", "pnpm", "config", "rc"),
			filepath.Join(home, ".config", "pnpm", "rc"),
		)
	}
	if cwd != "" {
		if st, err := os.Stat(filepath.Join(cwd, "pnpm-workspace.yaml")); err == nil && !st.IsDir() {
			out["workspace"] = true
		}
	}
	for _, p := range candidates {
		if !budgetOK(deadline) {
			break
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		mergeNpmrcMap(out, string(raw))
	}
	if len(out) == 0 {
		return nil, nil
	}
	login = npmLoginIdentityFromNpmrc(out)
	scrubAuthKeys(out)
	if len(out) == 0 {
		return nil, login
	}
	return out, login
}

func readYarnConfigNative(cwd string, deadline time.Time) any {
	if !budgetOK(deadline) {
		return nil
	}
	out := map[string]any{}
	for _, name := range []string{".yarnrc.yml", ".yarnrc"} {
		if !budgetOK(deadline) {
			break
		}
		path := filepath.Join(cwd, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.HasSuffix(name, ".yml") {
			mergeYarnYmlFlat(out, string(raw))
		} else {
			mergeNpmrcMap(out, string(raw))
		}
	}
	if home, err := os.UserHomeDir(); err == nil && budgetOK(deadline) {
		if raw, err := os.ReadFile(filepath.Join(home, ".yarnrc.yml")); err == nil {
			mergeYarnYmlFlat(out, string(raw))
		}
		if raw, err := os.ReadFile(filepath.Join(home, ".yarnrc")); err == nil {
			mergeNpmrcMap(out, string(raw))
		}
	}
	if len(out) == 0 {
		return nil
	}
	scrubAuthKeys(out)
	return out
}

func mergeYarnYmlFlat(dst map[string]any, content string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:colon])
		v := strings.TrimSpace(line[colon+1:])
		if k == "" || v == "" || v == "|" || v == ">" {
			continue
		}
		if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
			continue
		}
		v = strings.Trim(v, `"'`)
		dst[k] = v
	}
}

func yarnProfileFromConfig(cfg any) any {
	m, ok := cfg.(map[string]any)
	if !ok || len(m) == 0 {
		return npmProfileFromConfig(nil)
	}
	profile := map[string]any{}
	for _, k := range []string{"npmRegistryServer", "httpProxy", "httpsProxy"} {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			profile[k] = strings.TrimSpace(v)
		}
	}
	if len(profile) == 0 {
		return npmProfileFromConfig(cfg)
	}
	profile["source"] = "yarnrc"
	return profile
}

func mergeNpmrcMap(dst map[string]any, content string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if k == "" {
			continue
		}
		dst[k] = v
	}
}

func scrubAuthKeys(m map[string]any) {
	for k := range m {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "authtoken") ||
			strings.Contains(lk, "_auth") ||
			strings.HasSuffix(lk, ":_password") ||
			strings.Contains(lk, "password") ||
			strings.Contains(lk, "token") && !strings.Contains(lk, "init") {
			delete(m, k)
		}
	}
}

// ContextJSONMap returns a log-safe summary (no profile/config bodies).
func (c RequestContext) ContextJSONMap() map[string]any {
	m := map[string]any{
		"desktop": map[string]any{"pwd": c.Pwd},
		"nvm": map[string]any{
			"shim":         c.Shim,
			"node_version": c.NodeVersion,
		},
	}
	if c.PMFamily != "" {
		m[c.PMFamily+"_user"] = c.User != ""
		m[c.PMFamily+"_config_present"] = c.Config != nil
		if c.PMFamily == "npm" || c.PMFamily == "pnpm" {
			m[c.PMFamily+"_authenticated"] = c.Authenticated
		}
	}
	return m
}

// MustMarshalJSON is helpers for tests.
func MustMarshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

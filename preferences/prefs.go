package preferences

import "strings"

var (
	org    string
	subkey string
	app    string
)

var ROOT string
var ROOTS []string
var POLICY_ROOTS []string
var ACL_ROOTS []string
var MACHINE_PREFERENCE_ROOT string
var USER_PREFERENCE_ROOT string
var MACHINE_POLICY_ROOT string
var USER_POLICY_ROOT string
var NVM_CMD string

func init() {
	reload()
}

func reload() {
	USER_PREFERENCE_ROOT = joinRoot("HKCU/Software", org, subkey, app)
	MACHINE_PREFERENCE_ROOT = joinRoot("HKLM/SOFTWARE", org, subkey, app)
	USER_POLICY_ROOT = joinRoot("HKCU/Software/Policies", org, app)
	MACHINE_POLICY_ROOT = joinRoot("HKLM/SOFTWARE/Policies", org, app)

	ROOT = USER_PREFERENCE_ROOT
	ROOTS = []string{MACHINE_POLICY_ROOT, USER_POLICY_ROOT, MACHINE_PREFERENCE_ROOT, ROOT}
	POLICY_ROOTS = []string{MACHINE_POLICY_ROOT, USER_POLICY_ROOT}
	ACL_ROOTS = []string{USER_POLICY_ROOT, MACHINE_POLICY_ROOT, MACHINE_PREFERENCE_ROOT}
	NVM_CMD = joinRoot("HKCU/Software/Classes", app, "shell/open/command")
}

func joinRoot(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			filtered = append(filtered, part)
		}
	}

	return strings.Join(filtered, "/")
}

package preferences

import "strings"

var (
	org    string
	subkey string
	app    string
)

var ROOT = strings.Join([]string{"HKCU/Software", org, subkey, app}, "/")
var ROOTS = []string{ROOT}
var NVM_CMD = strings.Join([]string{"HKCU/Software/Classes", app, "shell/open/command"}, "/")

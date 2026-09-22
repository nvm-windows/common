//go:build windows

package verifycache

import (
	"os"
	"path/filepath"
	"strings"

	"common/system"
)

var (
	parentImagePathFn    = system.ParentProcessImagePath
	ancestorImagePathsFn = system.ListAncestorImagePaths
	nvmExeDirFn          = nvmExeDir
	allowSignChanged     bool
)

func nvmExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// SetAllowSignChanged marks this nvm.exe process as allowed to resign
// disk-changed untrusted launchers. Set only after parent-tree checks.
func SetAllowSignChanged(v bool) {
	allowSignChanged = v
}

// AllowSignChanged reports whether this process passed parent-tree authorization.
func AllowSignChanged() bool {
	return allowSignChanged
}

func shimDirFromSettings() (string, error) {
	dataRoot, err := dataRootFromSettings()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataRoot, ".shim"), nil
}

func fileStem(path string) string {
	base := filepath.Base(strings.TrimSpace(path))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func isPackageManagerStem(stem string) bool {
	switch strings.ToLower(strings.TrimSpace(stem)) {
	case "npm", "npx", "pnpm", "yarn", "yarnpkg", "corepack", "vlt", "node":
		return true
	default:
		return false
	}
}

func pathUnderDir(path, dir string) bool {
	path = filepath.Clean(path)
	dir = filepath.Clean(dir)
	if path == "" || dir == "" || dir == "." {
		return false
	}
	if strings.EqualFold(path, dir) {
		return true
	}
	prefix := dir + string(filepath.Separator)
	if len(path) < len(prefix) {
		return false
	}
	return strings.EqualFold(path[:len(prefix)], prefix)
}

func nestedUnderNonPmShim(ancestors []string, shimDir string) bool {
	for _, image := range ancestors {
		if !pathUnderDir(image, shimDir) {
			continue
		}
		if !isPackageManagerStem(fileStem(image)) {
			return true
		}
	}
	return false
}

// signChangedAuthorizedByShimParent is the gate for user `npm i -g`.
// Parent must be a package-manager image under .shim, and no non-PM global
// shim may appear in the ancestor list (nested self-update).
func signChangedAuthorizedByShimParent(parent string, ancestors []string, shimDir string) bool {
	if strings.TrimSpace(parent) == "" || strings.TrimSpace(shimDir) == "" {
		return false
	}
	if !pathUnderDir(parent, shimDir) {
		return false
	}
	if !isPackageManagerStem(fileStem(parent)) {
		return false
	}
	return !nestedUnderNonPmShim(ancestors, shimDir)
}

// AuthorizeSignChangedFromParent inspects the live process tree. Setting
// NVM_SIGN_CHANGED_MODULES in the environment is not sufficient and is ignored.
func AuthorizeSignChangedFromParent() bool {
	shimDir, err := shimDirFromSettings()
	if err != nil {
		return false
	}
	return signChangedAuthorizedByShimParent(parentImagePathFn(), ancestorImagePathsFn(), shimDir)
}

// ParentIsNvmReshim is true when this process was spawned by ProgramRoot\utils\reshim.exe.
func ParentIsNvmReshim() bool {
	parent := parentImagePathFn()
	dir := nvmExeDirFn()
	if parent == "" || dir == "" {
		return false
	}
	want := filepath.Join(dir, "utils", "reshim.exe")
	return strings.EqualFold(filepath.Clean(parent), filepath.Clean(want))
}

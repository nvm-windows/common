//go:build windows

package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const kfDontVerify uint32 = 0x00004000

type installRootProtect struct {
	subtree []string
	exact   []string
}

// CheckInstallRootAllowed refuses Node.js storage in OS, profile, or NVM program folders.
func CheckInstallRootAllowed(path string) error {
	abs, err := normalizeInstallRootPath(path)
	if err != nil {
		return fmt.Errorf("%s\n\nRequested path: %s", InstallRootDeniedMessage(), strings.TrimSpace(path))
	}
	if installRootDenied(abs, defaultInstallRootProtect()) {
		return fmt.Errorf("%s\n\nRequested path: %s", InstallRootDeniedMessage(), abs)
	}
	return nil
}

// IsSafeToDeleteInstallRoot reports whether uninstall may DelTree the storage path.
func IsSafeToDeleteInstallRoot(path string) bool {
	return CheckInstallRootAllowed(path) == nil
}

func normalizeInstallRootPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"'`)
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	path = os.ExpandEnv(path)
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	path = stripExtendedPathPrefix(path)
	if isUNCPath(path) {
		return "", fmt.Errorf("unc path")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func stripExtendedPathPrefix(path string) string {
	if len(path) >= 4 && path[:4] == `\\?\` {
		rest := path[4:]
		if len(rest) >= 4 && strings.EqualFold(rest[:4], `UNC\`) {
			return `\\` + rest[4:]
		}
		return rest
	}
	return path
}

func isUNCPath(path string) bool {
	if len(path) < 2 || path[0] != '\\' || path[1] != '\\' {
		return false
	}
	if len(path) >= 4 && path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\' {
		return false
	}
	return true
}

func defaultInstallRootProtect() installRootProtect {
	var p installRootProtect

	addSubtree := func(paths ...string) {
		for _, path := range paths {
			path = filepath.Clean(strings.TrimSpace(path))
			if path == "" || path == "." {
				continue
			}
			p.subtree = append(p.subtree, path)
		}
	}
	addExact := func(paths ...string) {
		for _, path := range paths {
			path = filepath.Clean(strings.TrimSpace(path))
			if path == "" || path == "." {
				continue
			}
			p.exact = append(p.exact, path)
		}
	}

	win := knownFolder(windows.FOLDERID_Windows, "SystemRoot", "windir")
	sys := knownFolder(windows.FOLDERID_System)
	sysx86 := knownFolder(windows.FOLDERID_SystemX86)
	pf := knownFolder(windows.FOLDERID_ProgramFiles, "ProgramFiles", "ProgramW6432")
	pf86 := knownFolder(windows.FOLDERID_ProgramFilesX86, "ProgramFiles(x86)")
	pfCommon := knownFolder(windows.FOLDERID_ProgramFilesCommon)
	pfCommon86 := knownFolder(windows.FOLDERID_ProgramFilesCommonX86)
	programData := knownFolder(windows.FOLDERID_ProgramData, "ProgramData", "ALLUSERSPROFILE")

	addSubtree(win, sys, sysx86, pf, pf86, pfCommon, pfCommon86, programData)
	if win != "" {
		addSubtree(filepath.Join(win, "WinSxS"))
	}
	if pf != "" {
		addSubtree(filepath.Join(pf, "WindowsApps"))
	}
	if pf86 != "" {
		addSubtree(filepath.Join(pf86, "WindowsApps"))
	}

	addExact(driveRoots()...)
	for _, root := range driveRoots() {
		addExact(filepath.Join(root, "$Recycle.Bin"))
	}

	profile := knownFolder(windows.FOLDERID_Profile, "USERPROFILE")
	local := knownFolder(windows.FOLDERID_LocalAppData, "LOCALAPPDATA")
	roaming := knownFolder(windows.FOLDERID_RoamingAppData, "APPDATA")
	localLow := knownFolder(windows.FOLDERID_LocalAppDataLow)
	publicDir := knownFolder(windows.FOLDERID_Public, "PUBLIC")
	userPrograms := knownFolder(windows.FOLDERID_UserProgramFiles)

	addExact(
		profile,
		local,
		roaming,
		localLow,
		publicDir,
		knownFolder(windows.FOLDERID_Desktop),
		knownFolder(windows.FOLDERID_Documents),
		knownFolder(windows.FOLDERID_Downloads),
		knownFolder(windows.FOLDERID_Pictures),
		knownFolder(windows.FOLDERID_Videos),
		knownFolder(windows.FOLDERID_Music),
		knownFolder(windows.FOLDERID_PublicDesktop),
		knownFolder(windows.FOLDERID_PublicDocuments),
		knownFolder(windows.FOLDERID_PublicDownloads),
		knownFolder(windows.FOLDERID_PublicPictures),
		knownFolder(windows.FOLDERID_PublicVideos),
		knownFolder(windows.FOLDERID_PublicMusic),
		knownFolder(windows.FOLDERID_StartMenu),
		knownFolder(windows.FOLDERID_CommonStartMenu),
		knownFolder(windows.FOLDERID_Startup),
		knownFolder(windows.FOLDERID_CommonStartup),
		userPrograms,
	)
	if local != "" {
		addExact(filepath.Join(local, "Microsoft"))
		if userPrograms == "" {
			addExact(filepath.Join(local, "Programs"))
		}
	}
	if profile != "" {
		addExact(
			filepath.Join(profile, "Downloads"),
			filepath.Join(profile, "Desktop"),
			filepath.Join(profile, "Documents"),
			filepath.Join(profile, "Pictures"),
			filepath.Join(profile, "Videos"),
			filepath.Join(profile, "Music"),
		)
	}

	for _, root := range nvmProgramRoots(local, pf, pf86) {
		addExact(root)
		addExact(
			filepath.Join(root, ".shim"),
			filepath.Join(root, ".nodejs"),
			filepath.Join(root, "utils"),
		)
	}

	return p
}

func nvmProgramRoots(local, pf, pf86 string) []string {
	roots := make([]string, 0, 4)
	add := func(path string) {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "" || path == "." {
			return
		}
		for _, existing := range roots {
			if equalFoldPath(existing, path) {
				return
			}
		}
		roots = append(roots, path)
	}
	if local != "" {
		add(filepath.Join(local, "Author Software", "nvm"))
	}
	if pf != "" {
		add(filepath.Join(pf, "Author Software", "nvm"))
	}
	if pf86 != "" {
		add(filepath.Join(pf86, "Author Software", "nvm"))
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if strings.Contains(strings.ToLower(dir), `\author software\nvm`) {
			add(dir)
		}
	}
	return roots
}

func installRootDenied(abs string, protect installRootProtect) bool {
	for _, root := range protect.subtree {
		if pathUnderOrEqual(abs, root) {
			return true
		}
	}
	for _, root := range protect.exact {
		if equalFoldPath(abs, root) {
			return true
		}
	}
	protected := make([]string, 0, len(protect.subtree)+len(protect.exact))
	protected = append(protected, protect.subtree...)
	protected = append(protected, protect.exact...)
	for _, child := range protected {
		if pathIsStrictParent(abs, child) {
			return true
		}
	}
	return false
}

func pathUnderOrEqual(child, parent string) bool {
	child = filepath.Clean(child)
	parent = filepath.Clean(parent)
	if parent == "" || parent == "." || child == "" || child == "." {
		return false
	}
	if equalFoldPath(child, parent) {
		return true
	}
	c := strings.ToLower(child)
	p := strings.ToLower(parent)
	sep := string(os.PathSeparator)
	if !strings.HasSuffix(p, sep) {
		p += sep
	}
	return strings.HasPrefix(c, p)
}

func pathIsStrictParent(parent, child string) bool {
	return pathUnderOrEqual(child, parent) && !equalFoldPath(parent, child)
}

func knownFolder(id *windows.KNOWNFOLDERID, envNames ...string) string {
	if id != nil {
		p, err := windows.KnownFolderPath(id, kfDontVerify)
		if err == nil && strings.TrimSpace(p) != "" {
			return filepath.Clean(p)
		}
	}
	for _, name := range envNames {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return filepath.Clean(v)
		}
	}
	return ""
}

func driveRoots() []string {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("GetLogicalDrives")
	r1, _, _ := proc.Call()
	mask := uint32(r1)
	if mask == 0 {
		return nil
	}
	out := make([]string, 0, 4)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		out = append(out, string(rune('A'+i))+`:\`)
	}
	return out
}

//go:build windows

package verifycache

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"common/settings"
	"common/verify"

	"golang.org/x/sys/windows"
)

const maxSignScriptPathBytes = 32 * 1024

var (
	parentPIDFn             = func() uint32 { return uint32(os.Getppid()) }
	stdinPipeServerPIDFn    = stdinPipeServerPID
	verifyParentPublisherFn = verifyParentPublisher

	procGetNamedPipeServerProcessId = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeServerProcessId")
)

func verifyParentPublisher(parent string) error {
	return verify.VerifySamePublisherAsExecutable(parent)
}

func stdinPipeServerPID() (uint32, bool) {
	h := windows.Handle(os.Stdin.Fd())
	ft, err := windows.GetFileType(h)
	if err != nil || ft != windows.FILE_TYPE_PIPE {
		return 0, false
	}
	var pid uint32
	r1, _, _ := procGetNamedPipeServerProcessId.Call(uintptr(h), uintptr(unsafe.Pointer(&pid)))
	if r1 == 0 || pid == 0 {
		return 0, false
	}
	return pid, true
}

// AuthorizeSignScriptFromParent is the --sign-script gate. The caller must be
// nvm.exe spawned by a signed proxy image, with the path on an anonymous pipe
// whose server PID is that parent. argv is not a trust source.
func AuthorizeSignScriptFromParent() error {
	dataRoot, err := dataRootFromSettings()
	if err != nil {
		return fmt.Errorf("sign-script refused: %w", err)
	}
	parent := parentImagePathFn()
	if !parentIsNvmProxy(parent, dataRoot) {
		return fmt.Errorf("sign-script refused: parent is not proxy")
	}
	if err := verifyParentPublisherFn(parent); err != nil {
		return fmt.Errorf("sign-script refused: %w", err)
	}
	pipePID, ok := stdinPipeServerPIDFn()
	if !ok {
		return fmt.Errorf("sign-script refused: missing proxy pipe")
	}
	if pipePID != parentPIDFn() {
		return fmt.Errorf("sign-script refused: pipe is not from parent")
	}
	return nil
}

// ReadSignScriptPath reads one launcher path from the proxy pipe. Extra
// command-line arguments are ignored by design; this is the only path source.
func ReadSignScriptPath(r io.Reader) (string, error) {
	limited := io.LimitReader(r, maxSignScriptPathBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("sign-script refused: %w", err)
	}
	if len(raw) > maxSignScriptPathBytes {
		return "", fmt.Errorf("sign-script refused: path too long")
	}
	scriptPath := strings.TrimSpace(string(raw))
	if scriptPath == "" {
		return "", fmt.Errorf("sign-script refused: empty path")
	}
	if strings.ContainsAny(scriptPath, "\x00\n\r") {
		return "", fmt.Errorf("sign-script refused: invalid path")
	}
	return scriptPath, nil
}

// IsDelegatedLauncherPath is true for .cmd/.bat/.js files NVM proxy would
// launch: under the installs root, Yarn Classic global bin, pnpm home bin,
// or the roaming npm prefix.
func IsDelegatedLauncherPath(scriptPath string) bool {
	scriptPath = filepath.Clean(strings.TrimSpace(scriptPath))
	if scriptPath == "" || scriptPath == "." {
		return false
	}
	ext := strings.ToLower(filepath.Ext(scriptPath))
	if ext != ".cmd" && ext != ".bat" && ext != ".js" {
		return false
	}
	installRoot := filepath.Clean(strings.TrimSpace(settings.Global().Root))
	if installRoot != "" && installRoot != "." && pathUnderDir(scriptPath, installRoot) {
		return true
	}
	if dir := yarnClassicGlobalBinDir(); dir != "" && pathUnderDir(scriptPath, dir) {
		return true
	}
	if dir := pnpmGlobalBinDir(); dir != "" && pathUnderDir(scriptPath, dir) {
		return true
	}
	if dir := npmRoamingBinDir(); dir != "" && pathUnderDir(scriptPath, dir) {
		return true
	}
	return false
}

func parentIsNvmProxy(parent, dataRoot string) bool {
	parent = filepath.Clean(strings.TrimSpace(parent))
	dataRoot = filepath.Clean(strings.TrimSpace(dataRoot))
	if parent == "" || dataRoot == "" || dataRoot == "." {
		return false
	}
	proxy := filepath.Join(dataRoot, "proxy.exe")
	if strings.EqualFold(parent, proxy) {
		return true
	}
	shim := filepath.Join(dataRoot, ".shim")
	if !pathUnderDir(parent, shim) {
		return false
	}
	if strings.EqualFold(filepath.Base(parent), "node.exe") {
		return false
	}
	if !strings.EqualFold(filepath.Ext(parent), ".exe") {
		return false
	}
	return filesHaveSameContents(parent, proxy)
}

func yarnClassicGlobalBinDir() string {
	local := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if local == "" {
		return ""
	}
	return filepath.Join(local, "Yarn", "bin")
}

func pnpmGlobalBinDir() string {
	home := strings.TrimSpace(os.Getenv("PNPM_HOME"))
	if home == "" {
		return ""
	}
	return filepath.Join(home, "bin")
}

func npmRoamingBinDir() string {
	appdata, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	appdata = strings.TrimSpace(appdata)
	if appdata == "" {
		return ""
	}
	return filepath.Join(appdata, "npm")
}

func filesHaveSameContents(leftPath, rightPath string) bool {
	left, err := os.Open(leftPath)
	if err != nil {
		return false
	}
	defer left.Close()
	right, err := os.Open(rightPath)
	if err != nil {
		return false
	}
	defer right.Close()
	leftInfo, err := left.Stat()
	if err != nil {
		return false
	}
	rightInfo, err := right.Stat()
	if err != nil {
		return false
	}
	if leftInfo.Size() != rightInfo.Size() {
		return false
	}
	bufL := make([]byte, 8192)
	bufR := make([]byte, 8192)
	for {
		nL, errL := left.Read(bufL)
		nR, errR := right.Read(bufR)
		if nL != nR || !bytes.Equal(bufL[:nL], bufR[:nR]) {
			return false
		}
		if errL == io.EOF && errR == io.EOF {
			return true
		}
		if errL != nil && errL != io.EOF {
			return false
		}
		if errR != nil && errR != io.EOF {
			return false
		}
		if (errL == io.EOF) != (errR == io.EOF) {
			return false
		}
	}
}

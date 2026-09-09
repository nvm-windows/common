package license

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Community program-root constants aligned with the Inno DefaultDirName /
// ForceProgramRootDirectory layout (%LOCALAPPDATA%\Author Software\nvm).
const (
	CommunityOrgLabel = "Author Software"
	CommunityAlias    = "nvm"

	// LayoutWarnCode is the human-facing event tag for unsupported community program roots.
	LayoutWarnCode = "NVM4101"
	// LayoutWarnEventID is the classic Application log EventId for layout warnings.
	LayoutWarnEventID = 4101
)

// ProgramRootCheck is the result of CheckCommunityProgramRoot.
type ProgramRootCheck struct {
	OK                bool
	SkippedCommercial bool
	ProgramRoot       string
	ExpectedPrefix    string
	Message           string
}

// isCommunityEditionForLayout is injectable for tests.
var isCommunityEditionForLayout = func() bool {
	return Edition() == communityEdition
}

// localAppDataDir is injectable for tests.
var localAppDataDir = func() (string, error) {
	if v := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); v != "" {
		return filepath.Clean(v), nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(dir), nil
}

// ExpectedCommunityProgramRootPrefix returns the LocalAppData program-root
// prefix community builds are designed and supported under.
func ExpectedCommunityProgramRootPrefix() (string, error) {
	base, err := localAppDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(base, CommunityOrgLabel, CommunityAlias)), nil
}

// CheckCommunityProgramRoot reports whether programRoot is under the expected
// community LocalAppData install prefix. Commercial editions are skipped.
// Warnings are advisory (unsupported / trust-boundary), not a hard failure.
func CheckCommunityProgramRoot(programRoot string) ProgramRootCheck {
	root := filepath.Clean(strings.TrimSpace(programRoot))
	result := ProgramRootCheck{ProgramRoot: root}

	if !isCommunityEditionForLayout() {
		result.OK = true
		result.SkippedCommercial = true
		return result
	}

	expected, err := ExpectedCommunityProgramRootPrefix()
	if err != nil {
		result.OK = true // fail open if we cannot resolve LocalAppData
		result.Message = fmt.Sprintf("%s: unable to resolve expected community program root: %v", LayoutWarnCode, err)
		return result
	}
	result.ExpectedPrefix = expected

	if root == "" || root == "." {
		result.Message = layoutWarnMessage(root, expected)
		return result
	}

	if pathUnderPrefix(root, expected) {
		result.OK = true
		return result
	}

	result.Message = layoutWarnMessage(root, expected)
	return result
}

func layoutWarnMessage(actual, expected string) string {
	return fmt.Sprintf(
		"%s: NVM for Windows (Community) is running from a location outside its expected per-user install root (%s). "+
			"Community builds are designed and supported only when program files live under that root so per-user isolation and directory protections apply. "+
			"Execution from another path is an unsupported configuration and may increase risk if that location is writable by other users or outside the tested layout. "+
			"Move/reinstall to the default LocalAppData location, or use NVM for Windows Certified Builds for an IT-managed Program Files installation. "+
			"Details: %s | expected: %s",
		LayoutWarnCode,
		expected,
		actual,
		expected,
	)
}

func pathUnderPrefix(path, prefix string) bool {
	path = filepath.Clean(path)
	prefix = filepath.Clean(prefix)
	if path == "" || prefix == "" {
		return false
	}
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
		prefix = strings.ToLower(prefix)
	}
	if path == prefix {
		return true
	}
	rel, err := filepath.Rel(prefix, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

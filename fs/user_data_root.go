package fs

import (
	"os"
	"path/filepath"
	"strings"
)

var serviceProfileLocalAppDataSuffixes = []string{
	`\windows\system32\config\systemprofile\appdata\local`,
	`\windows\serviceprofiles\localservice\appdata\local`,
	`\windows\serviceprofiles\networkservice\appdata\local`,
}

// UserDataRoot returns the fixed per-user runtime data directory
// (%LOCALAPPDATA%\Author Software\nvm). InstallRoot (version trees) may live
// elsewhere; PATH .nodejs and reshim always use this root.
func UserDataRoot() (string, bool) {
	return UserDataRootFrom(os.LookupEnv)
}

// UserDataRootFrom is the testable form of UserDataRoot.
func UserDataRootFrom(lookupEnv func(string) (string, bool)) (string, bool) {
	local, ok := lookupEnv("LOCALAPPDATA")
	if !ok {
		return "", false
	}
	local = strings.TrimSpace(local)
	if local == "" || isServiceProfileLocalAppData(local) {
		return "", false
	}
	return filepath.Join(local, "Author Software", "nvm"), true
}

func isServiceProfileLocalAppData(localAppData string) bool {
	cleaned := strings.ToLower(filepath.Clean(localAppData))
	for _, root := range serviceProfileLocalAppDataSuffixes {
		if strings.HasSuffix(cleaned, root) {
			return true
		}
	}
	return false
}

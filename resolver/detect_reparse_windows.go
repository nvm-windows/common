//go:build windows

package resolver

import "os"

// detectFileIsReparse reports symlink detect files so AutoUse does not follow
// planted links (nvm-sh GHSA-j6ch-mq5c-3h4x class). ModeSymlink covers the
// typical .nvmrc → secret file plant; junctions are uncommon for this vector.
func detectFileIsReparse(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}

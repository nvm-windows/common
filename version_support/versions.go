package version_support

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// 10.8.0 (EOL 2021-04-30) was the first version of Node bundling npm.
// nvm-windows no longer tracks old npm download sources.
// Prevent installation of versions below 10.8.0
// ARM support was added in Node 12 experimentally, but hasn't been
// stable since v20.0.0, so require at least v20.0.0 for ARM devices.
func IsSupportedVersion(version string) (bool, error) {
	semver := strings.Split(version, ".")
	major, _ := strconv.Atoi(semver[0])
	minor, _ := strconv.Atoi(semver[1])

	if major < 10 || (major == 10 && minor < 8) {
		return false, fmt.Errorf("minimum supported: v10.8.0")
	}

	if strings.HasPrefix(runtime.GOARCH, "arm") {
		if major < 20 {
			return false, fmt.Errorf("minimum ARM support: v20.0.0")
		}
	}

	return true, nil
}

//go:build !windows

package resolver

// detectFileIsReparse is a no-op off Windows.
func detectFileIsReparse(path string) bool {
	_ = path
	return false
}

//go:build !windows

package fs

func LockShimDirectory(path string) error {
	return nil
}

func UnlockShimDirectory(path string) error {
	return nil
}

func LockProxyExecutable(path string) error {
	return nil
}

func UnlockProxyExecutable(path string) error {
	return nil
}

func RunWithRuntimeShimWrite(shimDir, proxyPath string, fn func() error) error {
	return fn()
}

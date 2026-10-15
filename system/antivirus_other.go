//go:build !windows

package system

func init() {
	detectAntivirusProducts = func() []string { return nil }
}

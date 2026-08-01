package verifycache

import (
	"testing"
)

func TestCacheKeyForPathLowercases(t *testing.T) {
	left, err := cacheKeyForPath(`C:\NVM\installs\v22\node.exe`)
	if err != nil {
		t.Fatalf("cacheKeyForPath(left) error = %v", err)
	}
	right, err := cacheKeyForPath(`c:\nvm\installs\v22\node.exe`)
	if err != nil {
		t.Fatalf("cacheKeyForPath(right) error = %v", err)
	}
	if left != right {
		t.Fatalf("cacheKeyForPath() = %q vs %q, want equal", left, right)
	}
}

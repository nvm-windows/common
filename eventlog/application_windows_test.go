//go:build windows

package eventlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestShouldWriteThrottled(t *testing.T) {
	dir := t.TempDir()
	stamp := filepath.Join(dir, "warn.stamp")
	if !shouldWriteThrottled(stamp, time.Hour) {
		t.Fatal("missing stamp should allow write")
	}
	if err := touchThrottleStamp(stamp); err != nil {
		t.Fatal(err)
	}
	if shouldWriteThrottled(stamp, time.Hour) {
		t.Fatal("fresh stamp should suppress write")
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stamp, past, past); err != nil {
		t.Fatal(err)
	}
	if !shouldWriteThrottled(stamp, time.Hour) {
		t.Fatal("expired stamp should allow write")
	}
}

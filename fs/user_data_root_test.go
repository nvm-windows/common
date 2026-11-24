package fs

import (
	"path/filepath"
	"testing"
)

func TestUserDataRootFromUsesLocalAppData(t *testing.T) {
	got, ok := UserDataRootFrom(func(name string) (string, bool) {
		if name == "LOCALAPPDATA" {
			return `C:\Users\a\AppData\Local`, true
		}
		return "", false
	})
	if !ok {
		t.Fatal("UserDataRootFrom() ok = false, want true")
	}
	want := filepath.Join(`C:\Users\a\AppData\Local`, "Author Software", "nvm")
	if got != want {
		t.Fatalf("UserDataRootFrom() = %q, want %q", got, want)
	}
}

func TestUserDataRootFromSkipsServiceProfiles(t *testing.T) {
	_, ok := UserDataRootFrom(func(name string) (string, bool) {
		if name == "LOCALAPPDATA" {
			return `C:\Windows\ServiceProfiles\LocalService\AppData\Local`, true
		}
		return "", false
	})
	if ok {
		t.Fatal("service profile LOCALAPPDATA must not yield a data root")
	}
}

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"common/settings"
)

func processRoot(value *string) (deferredFn func(), err error) {
	s := settings.Global()
	if !s.AllowRootDirChange {
		err = fmt.Errorf("root directory change blocked by local policy")
		return
	}

	*value = strings.Trim(*value, `"`) // Remove potential quotes from input

	sourceRoot := filepath.Clean(s.Root)
	targetRoot := filepath.Clean(settings.Expand(*value))

	if strings.EqualFold(sourceRoot, targetRoot) {
		err = fmt.Errorf("root value is already %s", *value)
		return
	}

	deferredFn = func() {
		dir, err := os.ReadDir(sourceRoot)
		if err != nil {
			return
		}

		versions := []string{}

		for _, entry := range dir {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "v") {
				versions = append(versions, entry.Name())
			}
		}

		if len(versions) == 0 {
			return
		}

		fmt.Println("\nIf you wish to use the same Node.js versions in the new root, please move the following directories\n")
		for _, v := range versions {
			fmt.Printf("      %s\n", v)
		}
		fmt.Printf("\nFrom: %s\nTo:   %s\n\n", sourceRoot, targetRoot)
	}

	return
}

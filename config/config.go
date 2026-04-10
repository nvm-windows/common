package config

import "strings"

func Prepare(key, value *string) (skip bool, deferredFn func(), err error) {
	skip = false

	switch *key {
	case "root":
		deferredFn, err = processRoot(value)

		if err != nil && strings.Contains(err.Error(), "blocked") {
			skip = true
		}

		return
	}

	return
}

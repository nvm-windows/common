package license

import (
	"common/settings"
	"common/token"
)

func init() {
	token.AirGappedFn = func() bool { return settings.Global().AirGapped }
	token.LoadJwksCoseFn = settings.JwksCoseBytes
}

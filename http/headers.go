package http

import (
	"common/mirrorauth"
	gohttp "net/http"
)

func applyExtraHeaders(req *gohttp.Request) {
	if req == nil || req.URL == nil {
		return
	}

	for key, value := range mirrorauth.HeadersForURL(req.URL) {
		if key != "" && value != "" {
			req.Header.Set(key, value)
		}
	}
}

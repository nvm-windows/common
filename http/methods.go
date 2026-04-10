package http

import gohttp "net/http"

var global *Client

func HEAD(url string) (*gohttp.Response, error) {
	if global == nil {
		global = new()
	}

	return global.Head(url)
}

func GET(url string) (*gohttp.Response, error) {
	if global == nil {
		global = new()
	}

	return global.Get(url)
}

func DELETE(url string) (*gohttp.Response, error) {
	if global == nil {
		global = new()
	}

	return global.Delete(url)
}

func Request(req *gohttp.Request) (*gohttp.Response, error) {
	if global == nil {
		global = new()
	}

	return global.Request(req)
}

package http

import (
	"net/url"
	"strings"

	winreg "golang.org/x/sys/windows/registry"
)

const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func Proxy(rawURL string) (string, bool) {
	scheme := "http"
	if parsedURL, err := url.Parse(strings.TrimSpace(rawURL)); err == nil && parsedURL.Scheme != "" {
		scheme = strings.ToLower(parsedURL.Scheme)
	}

	handle, err := winreg.OpenKey(winreg.CURRENT_USER, internetSettingsKey, winreg.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer handle.Close()

	enabled, _, err := handle.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		return "", false
	}

	proxyServer, _, err := handle.GetStringValue("ProxyServer")
	if err != nil {
		return "", false
	}

	selected := selectProxyServer(proxyServer, scheme)
	if selected == "" {
		return "", false
	}

	return normalizeProxyAddress(selected), true
}

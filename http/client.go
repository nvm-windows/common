package http

import (
	"common/proxy"
	"common/settings"
	"crypto/tls"
	"errors"
	"fmt"
	gohttp "net/http"
	"net/url"
	"strings"
	"time"
)

var (
	appname string
	edition string
	version string
)

type Client struct {
	client *gohttp.Client
}

func new(allowInsecure ...bool) *Client {
	transport := gohttp.DefaultTransport.(*gohttp.Transport).Clone()
	transport.Proxy = proxyURLForRequest
	if len(allowInsecure) > 0 && allowInsecure[0] {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		client: &gohttp.Client{
			Timeout:   30 * time.Second,
			Transport: proxy.WrapTransport(transport),
		},
	}
}

func (c *Client) Head(url string) (*gohttp.Response, error) {
	url, err := normalizeURL(url)
	if err != nil {
		return nil, errors.New("invalid URL: " + err.Error())
	}

	req, err := makeRequest("HEAD", url)
	if err != nil {
		return nil, err
	}

	return c.client.Do(req)
}

func (c *Client) Get(url string) (*gohttp.Response, error) {
	url, err := normalizeURL(url)
	if err != nil {
		return nil, errors.New("invalid URL: " + err.Error())
	}

	req, err := makeRequest("GET", url)
	if err != nil {
		return nil, err
	}

	return c.client.Do(req)
}

func (c *Client) Delete(url string) (*gohttp.Response, error) {
	url, err := normalizeURL(url)
	if err != nil {
		return nil, errors.New("invalid URL: " + err.Error())
	}

	req, err := makeRequest("DELETE", url)
	if err != nil {
		return nil, err
	}

	return c.client.Do(req)
}

func (c *Client) Request(req *gohttp.Request) (*gohttp.Response, error) {
	// Implement the custom request logic here
	return c.client.Do(req)
}

// h1only returns a client that forces HTTP/1.1, used as a fallback when
// HTTP/2 stream errors occur (common in elevated/admin Windows contexts).
func h1only(allowInsecure ...bool) *Client {
	transport := gohttp.DefaultTransport.(*gohttp.Transport).Clone()
	transport.Proxy = proxyURLForRequest
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = make(map[string]func(string, *tls.Conn) gohttp.RoundTripper)
	if len(allowInsecure) > 0 && allowInsecure[0] {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		client: &gohttp.Client{
			Timeout:   30 * time.Second,
			Transport: proxy.WrapTransport(transport),
		},
	}
}

func makeRequest(method, url string) (*gohttp.Request, error) {
	req, err := gohttp.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s (%s)", appname, version, edition))

	return req, nil
}

func NormalizeURL(rawURL string) (string, error) {
	return normalizeURL(rawURL)
}

func normalizeURL(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}

	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)

	// Normalize path: remove trailing slashes and clean double slashes
	if u.Path != "" && u.Path != "/" {
		u.Path = strings.TrimRight(u.Path, "/")
		u.Path = cleanDuplicateSlashes(u.Path)
	}

	return u.String(), nil
}

// cleanDuplicateSlashes removes consecutive slashes from a path
func cleanDuplicateSlashes(path string) string {
	parts := strings.Split(path, "/")
	var cleaned []string
	for _, part := range parts {
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	result := "/" + strings.Join(cleaned, "/")
	return result
}

func proxyURLForRequest(req *gohttp.Request) (*url.URL, error) {
	configuredProxy := strings.TrimSpace(settings.Global().Proxy)
	if configuredProxy != "" {
		return parseProxyURL(configuredProxy)
	}

	envProxy, err := gohttp.ProxyFromEnvironment(req)
	if err != nil || envProxy != nil {
		return envProxy, err
	}

	if req == nil || req.URL == nil {
		return nil, nil
	}

	builtinProxy, ok := Proxy(req.URL.String())
	if !ok {
		return nil, nil
	}

	return parseProxyURL(builtinProxy)
}

func parseProxyURL(raw string) (*url.URL, error) {
	return url.Parse(normalizeProxyAddress(raw))
}

func normalizeProxyAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		return raw
	}
	return "http://" + raw
}

func selectProxyServer(raw, scheme string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if !strings.Contains(raw, "=") {
		return strings.TrimSpace(raw)
	}

	entries := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		pair := strings.SplitN(part, "=", 2)
		if len(pair) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(pair[0]))
		value := strings.TrimSpace(pair[1])
		if value != "" {
			entries[key] = value
		}
	}

	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if value := entries[scheme]; value != "" {
		return value
	}
	if value := entries["http"]; value != "" {
		return value
	}
	if value := entries["https"]; value != "" {
		return value
	}

	return ""
}

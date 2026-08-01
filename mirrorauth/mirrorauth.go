package mirrorauth

import "net/url"

// Implementation identifies which mirrorauth module is linked.
// "stub" = community/no-op; "certified" = mirror license JWT for Author mirrors.
func Implementation() string {
	return "stub"
}

// MirrorHost is the primary Author Node.js distribution mirror.
const MirrorHost = "mirror.author.io"

// AuthorMirrorDomainSuffix matches Author-hosted mirrors in the certified build.
const AuthorMirrorDomainSuffix = ".author.io"

// LicenseHeader is the HTTP header carrying the mirror license JWT.
const LicenseHeader = "X-Author-License"

// AuthorizationHeader is the HTTP header carrying the pre-issued access token JWT.
const AuthorizationHeader = "Authorization"

// HeadersForURL returns extra request headers for u. OSS builds return nil.
func HeadersForURL(u *url.URL) map[string]string {
	return nil
}

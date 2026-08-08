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

// ClearCachedLicenseJWT drops the in-process cached mirror license JWT, if any.
// OSS builds have no license JWT cache, so this always returns false.
func ClearCachedLicenseJWT() bool {
	return false
}

// SetAllowClaimFunc is a no-op in OSS builds.
func SetAllowClaimFunc(fn func() ([]string, error)) {}

// AllowVersionClaimExpansion is always true in OSS builds (no JWT builder).
func AllowVersionClaimExpansion() bool { return true }

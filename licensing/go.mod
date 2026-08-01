module common/license

go 1.26.2

replace common/fs v1.0.0 => ../fs

replace common/preferences v1.0.0 => ../../enhanced/go/preferences

replace common/registry v1.0.0 => ../registry

replace common/settings v1.0.0 => ../settings

replace common/token v1.0.0 => ../token

replace common/urlguard v1.0.0 => ../urlguard

replace common/http v1.0.0 => ../http

require (
	common/settings v1.0.0
	common/token v1.0.0
	github.com/golang-jwt/jwt/v5 v5.2.2
)

require (
	common/fs v1.0.0 // indirect
	common/preferences v1.0.0 // indirect
	common/registry v1.0.0 // indirect
	common/urlguard v1.0.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

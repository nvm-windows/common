module common/http

go 1.26.2

replace common/fs v1.0.0 => ../fs

replace common/preferences v1.0.0 => ../preferences

replace common/proxy v1.0.0 => ../proxy

replace common/registry v1.0.0 => ../registry

replace common/settings v1.0.0 => ../settings

replace common/urlguard v1.0.0 => ../urlguard

replace common/mirrorauth v1.0.0 => ../mirrorauth

require (
	common/fs v1.0.0
	common/mirrorauth v1.0.0
	common/proxy v1.0.0
	common/settings v1.0.0
	golang.org/x/sys v0.41.0
)

require (
	common/preferences v1.0.0 // indirect
	common/registry v1.0.0 // indirect
	common/urlguard v1.0.0 // indirect
)

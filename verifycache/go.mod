module common/verifycache

go 1.26.2

require (
	common/preferences v1.0.0
	common/registry v1.0.0
	common/settings v1.0.0
	common/verify v1.0.0
	golang.org/x/sys v0.41.0
)

require (
	common/fs v1.0.0
	common/urlguard v1.0.0 // indirect
)

replace common/preferences v1.0.0 => ../preferences

replace common/registry v1.0.0 => ../registry

replace common/settings v1.0.0 => ../settings

replace common/verify v1.0.0 => ../verify

replace common/fs v1.0.0 => ../fs

replace common/urlguard v1.0.0 => ../urlguard

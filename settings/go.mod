module common/settings

go 1.26.2

replace common/fs v1.0.0 => ../fs

replace common/preferences v1.0.0 => ../preferences

replace common/registry v1.0.0 => ../registry

replace common/urlguard v1.0.0 => ../urlguard

require (
	common/fs v1.0.0
	common/preferences v1.0.0
	common/registry v1.0.0
	common/urlguard v1.0.0
)

require golang.org/x/sys v0.41.0 // indirect

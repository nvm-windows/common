module common/config

go 1.26.2

replace common/fs v1.0.0 => ../fs

replace common/settings v1.0.0 => ../settings

replace common/preferences v1.0.0 => ../preferences

replace common/registry v1.0.0 => ../registry

replace common/urlguard v1.0.0 => ../urlguard

require (
	common/fs v1.0.0
	common/settings v1.0.0
)

require (
	common/preferences v1.0.0 // indirect
	common/registry v1.0.0 // indirect
	common/urlguard v1.0.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

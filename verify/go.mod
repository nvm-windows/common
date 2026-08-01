module common/verify

go 1.26.2

replace common/fs v1.0.0 => ../fs

replace common/preferences v1.0.0 => ../preferences

replace common/registry v1.0.0 => ../registry

replace common/settings v1.0.0 => ../settings

require (
	common/settings v1.0.0
	golang.org/x/sys v0.41.0
)

require (
	common/fs v1.0.0 // indirect
	common/preferences v1.0.0 // indirect
	common/registry v1.0.0 // indirect
)

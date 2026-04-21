module common/inspect

go 1.26.2

replace common/settings v1.0.0 => ../settings

require (
	common/settings v1.0.0
	github.com/coreybutler/go-where/v2 v2.1.2
	golang.org/x/sys v0.37.0
)

require github.com/coreybutler/go-fsutil v1.2.2 // indirect

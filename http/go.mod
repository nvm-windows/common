module common/http

go 1.26.2

replace common/proxy v1.0.0 => ../proxy

require (
  common/proxy v1.0.0
  common/settings v1.0.0
  golang.org/x/sys v0.41.0
)
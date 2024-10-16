module github.com/northbright/hasher

go 1.23.0

require (
	github.com/northbright/download v0.0.16
	github.com/northbright/httputil v1.2.3
	github.com/northbright/iocopy v1.13.7
)

require github.com/northbright/pathelper v1.0.8 // indirect

// Not good enough, need to hide it on pkg.go.dev
retract v1.0.0

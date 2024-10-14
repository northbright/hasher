module github.com/northbright/hasher

go 1.23.0

require (
	github.com/northbright/download v0.0.14
	github.com/northbright/iocopy v1.13.6
)

require (
	github.com/northbright/httputil v1.2.2 // indirect
	github.com/northbright/pathelper v1.0.8 // indirect
)

// Not good enough, need to hide it on pkg.go.dev
retract v1.0.0

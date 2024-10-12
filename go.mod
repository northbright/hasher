module github.com/northbright/hasher

go 1.23

toolchain go1.23.0

require (
	github.com/northbright/httputil v1.2.2
	github.com/northbright/iocopy v1.13.6
)

// Not good enough, need to hide it on pkg.go.dev
retract v1.0.0

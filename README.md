# hasher

hasher is a [Golang](https://golang.org) package provides functions to compute hash checksums. It's based on [iocopy](https://github.com/northbright/iocopy).

## Features
* Start a new goroutine to compute hash checksums
* Compute multiple hash checksums at one time
* Provide caller an event channel to receive [events](https://pkg.go.dev/github.com/northbright/iocopy#Event)
* The channel is closed automatically when the goroutine exits(an error occurs, user cancels, computing hash checksums is done)

## Supported Hash Functions
* `MD5`
* `SHA-1`
* `SHA-256`
* `SHA-512`
* `CRC-32`

## Docs
* <https://pkg.go.dev/github.com/northbright/hasher>

## Usage
* Check [examples](https://pkg.go.dev/github.com/northbright/hasher#pkg-examples)

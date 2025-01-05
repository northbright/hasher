package hasher_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/northbright/hasher"
	"github.com/northbright/iocopy"
)

func ExampleSupportedHashAlgs() {
	algs := hasher.SupportedHashAlgs()
	l := len(algs)

	for i, alg := range algs {
		fmt.Printf("%v: %v", i, alg)
		if i != l-1 {
			fmt.Printf("\n")
		}
	}

	// Output:
	// 0: CRC-32
	// 1: MD5
	// 2: SHA-1
	// 3: SHA-256
	// 4: SHA-512
}

func ExampleComputeChecksumsBufferWithProgress() {
	// SHA-256: dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
	url := "https://golang.google.cn/dl/go1.23.1.darwin-amd64.pkg"

	// Get response body(io.Reader) of the remote file.
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("http.Get() error: %v, url: %v", err, url)
		return
	}
	defer resp.Body.Close()

	// Try to get size of the file.
	str := resp.Header.Get("Content-Length")
	if len(str) == 0 {
		log.Printf("failed to get Content-Length")
		return
	}
	size, _ := strconv.ParseInt(str, 10, 64)

	ctx := context.Background()
	algs := []string{"MD5", "SHA-1", "SHA-256"}
	buf := make([]byte, 1024*640)

	n, checksums, err := hasher.ComputeChecksumsBufferWithProgress(
		// Context.
		ctx,
		// Hash algorithms.
		algs,
		// Reader.
		resp.Body,
		// Buffer.
		buf,
		// Total size.
		size,
		// Callback to report progress.
		iocopy.OnWrittenFunc(func(total, prev, current int64, percent float32) {
			log.Printf("%v / %v(%.2f%%) computed", prev+current, total, percent)
		}),
	)

	log.Printf("compute checksums done. %d bytes computed", n)
	for alg, checksum := range checksums {
		log.Printf("%s: %x", alg, checksum)
	}

	fmt.Printf("SHA-256: %x", checksums["SHA-256"])

	// Output:
	// SHA-256: dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
}

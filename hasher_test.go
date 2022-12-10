package hasher_test

import (
	"context"
	"fmt"
	"log"

	"github.com/northbright/hasher"
	"github.com/northbright/iocopy"
)

func ExampleNewStringsHasher() {
	// Example of computing strings hash.
	// Compute the SHA-256 hash of the strings in offical example:
	// https://pkg.go.dev/hash#example-package-BinaryMarshaler
	const (
		input1 = "The tunneling gopher digs downwards, "
		input2 = "unaware of what he will find."
	)

	var (
		// Specifiy 2 hash algorithms.
		hashAlgs = []string{"MD5", "SHA-256"}
		// Global checksums.
		checksums = make(map[string][]byte)
	)

	// Create a hasher with given hash algorithms and strings.
	h := hasher.NewStringsHasher(hashAlgs, input1, input2)

	// Start to compute the hash.
	ch := h.Start(context.Background(), 32*1024, 0)

	// Read iocopy.Event from the returned channel.
	for event := range ch {
		switch ev := event.(type) {
		case *iocopy.EventOK:
			// IO copy succeeded(computing hash completed).
			n := ev.Written()
			log.Printf("on EventOK: total %v written", n)

			// Get checksums.
			checksums = h.Checksums()
			// Print checksum of each algorithm.
			for alg, checksum := range checksums {
				log.Printf("%v: %x", alg, checksum)
			}
		}
	}

	// Output SHA-256 checksum.
	fmt.Printf("%x", checksums["SHA-256"])

	// Output:
	// 57d51a066f3a39942649cd9a76c77e97ceab246756ff3888659e6aa5a07f4a52
}

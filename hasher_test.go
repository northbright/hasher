package hasher_test

import (
	"fmt"
	"log"

	"github.com/northbright/hasher"
)

func ExampleHasher_ComputeStrings() {
	// Example of computing strings hash.
	// Compute the SHA-256 hash of the strings in offical example:
	// https://pkg.go.dev/hash#example-package-BinaryMarshaler
	const (
		input1 = "The tunneling gopher digs downwards, "
		input2 = "unaware of what he will find."
	)

	// Create a hasher with given hash algorithms.
	// Currently, it supports: "MD5", "SHA-1", "SHA-256", "SHA-512".
	// Call SupportedHashAlgs to get all available hash algorithms.
	h, _ := hasher.New("MD5", "SHA-256")

	// Compute the hashes of the strings.
	checksums, n, _ := h.ComputeStrings(input1, input2)

	// Show the checksums and count of written bytes.
	for alg, checksum := range checksums {
		log.Printf("%s: %x", alg, checksum)
	}
	log.Printf("%d bytes written", n)

	// Output SHA-256 checksum.
	fmt.Printf("%x", checksums["SHA-256"])

	// Output:
	// 57d51a066f3a39942649cd9a76c77e97ceab246756ff3888659e6aa5a07f4a52
}

package hasher_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/northbright/hasher"
	"github.com/northbright/iocopy"
)

func ExampleFromStrings() {
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
	h, _ := hasher.FromStrings([]string{input1, input2}, "MD5", "SHA-256")

	// Compute the hashes of the strings.
	checksums, n, _ := h.Compute(context.Background(), false)

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

func ExampleFromUrl() {
	// URL of Ubuntu release.
	// SHA-256:
	// 10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb
	downloadURL := "https://www.releases.ubuntu.com/jammy/ubuntu-22.04.1-live-server-amd64.iso"

	// Create a hasher from URL.
	// The total content length of the URL will be returned if possible.
	h, total, _ := hasher.FromUrl(downloadURL, "MD5", "SHA-256")

	// Start a worker goroutine to compute hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch := h.Start(
		// Context
		context.Background(),
		// Buffer size
		16*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond,
		// Try closing reader on exit
		true)

	// Read the events from the channel.
	for event := range ch {
		switch ev := event.(type) {
		case *iocopy.EventWritten:
			// n bytes have been written successfully.
			// Get the count of bytes.
			n := ev.Written()
			percent := float32(float64(n) / (float64(total) / float64(100)))
			log.Printf("on EventWritten: %v/%v bytes written(%.2f%%)", n, total, percent)

		case *iocopy.EventStop:
			// Context is canceled or
			// context's deadline exceeded.
			log.Printf("on EventStop: %v", ev.Err())

		case *iocopy.EventError:
			// an error occured.
			// Get the error.
			log.Printf("on EventError: %v", ev.Err())

		case *iocopy.EventOK:
			// IO copy succeeded.
			// Get the total count of written bytes.
			n := ev.Written()
			percent := float32(float64(n) / (float64(total) / float64(100)))
			log.Printf("on EventOK: %v/%v bytes written(%.2f%%)", n, total, percent)

			// Get the final SHA-256 checksum of the remote file.
			checksums := h.Checksums()
			fmt.Printf("SHA-256:\n%x", checksums["SHA-256"])
		}
	}

	// The event channel will be closed after:
	// (1). iocopy.EventError received.
	// (2). iocopy.EventStop received.
	// (3). iocopy.EventOK received.
	// The for-range loop exits when the channel is closed.
	log.Printf("h.Start() gouroutine exited and the event channel is closed")

	// Output:
	// SHA-256:
	// 10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb
}

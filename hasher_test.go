package hasher_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/northbright/hasher"
	"github.com/northbright/httputil"
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
	// Currently, it supports: "MD5", "SHA-1", "SHA-256", "SHA-512", "CRC-32".
	// Call SupportedHashAlgs to get all available hash algorithms.
	h, _ := hasher.FromStrings(
		// String slice
		[]string{input1, input2},
		// Hash algorithms
		"MD5", "SHA-256", "CRC-32")

	// Close the hasher after use.
	defer h.Close()

	// Compute the hashes of the strings.
	checksums, n, _ := h.Compute(context.Background())

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

	// Close the hasher after use.
	defer h.Close()

	// Start a worker goroutine to compute hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch := h.Start(
		// Context
		context.Background(),
		// Buffer size
		16*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

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
			fmt.Printf("SHA-256:\n%x\n", checksums["SHA-256"])

			// Verify the SHA-256 checksum.
			matched, alg := h.Match("10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb")
			fmt.Printf("matched: %v, matched hash algorithm: %v", matched, alg)
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
	// matched: true, matched hash algorithm: SHA-256
}

func ExampleFromUrlWithStates() {
	// states is used to save hashes states.
	var states = make(map[string][]byte)

	// computed is the number of bytes has been written / hashed.
	var computed int64 = 0

	// URL of Ubuntu release.
	// SHA-256:
	// 10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb
	downloadURL := "https://www.releases.ubuntu.com/jammy/ubuntu-22.04.1-live-server-amd64.iso"

	// Stage 1.
	// Create a hasher from URL.
	// The total content length of the URL will be returned if possible.
	h1, total, _ := hasher.FromUrl(downloadURL, "MD5", "SHA-256")

	// Close the hasher after use.
	defer h1.Close()

	// create a context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a worker goroutine to compute hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch := h1.Start(
		// Context
		ctx,
		// Buffer size
		16*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

	// Read the events from the channel.
	for event := range ch {
		switch ev := event.(type) {
		case *iocopy.EventWritten:
			// n bytes have been written successfully.
			// Get the count of bytes.
			computed = ev.Written()
			percent := float32(float64(computed) / (float64(total) / float64(100)))
			log.Printf("on EventWritten: %v/%v bytes written(%.2f%%)", computed, total, percent)
			// Stop computing hash when percent > 50%.
			if percent > 50 {
				cancel()
			}

		case *iocopy.EventStop:
			// Context is canceled or
			// context's deadline exceeded.
			log.Printf("on EventStop: %v", ev.Err())

			// Save the number of computed bytes.
			computed = ev.Written()

			// Save the hashes states.
			states, _ = h1.States()

		case *iocopy.EventError:
			// an error occured.
			// Get the error.
			log.Printf("on EventError: %v", ev.Err())

		case *iocopy.EventOK:
		}
	}

	// The event channel will be closed after:
	// (1). iocopy.EventError received.
	// (2). iocopy.EventStop received.
	// (3). iocopy.EventOK received.
	// The for-range loop exits when the channel is closed.
	log.Printf("Stage 1: h1.Start() gouroutine exited and the event channel is closed")

	// Stage 2.
	// Create a hasher from URL with number of computed bytes and
	// saved states to continue to compute hashes.
	h2, total, _ := hasher.FromUrlWithStates(
		// URL
		downloadURL,
		// Number of computed bytes
		computed,
		// States of hashes
		states)

	// Close the hasher after use.
	defer h2.Close()

	// Start a worker goroutine to compute hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch = h2.Start(
		// Context
		context.Background(),
		// Buffer size
		16*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

	newComputed := int64(0)

	// Read the events from the channel.
	for event := range ch {
		switch ev := event.(type) {
		case *iocopy.EventWritten:
			// n bytes have been written successfully.
			// Get the count of bytes.
			newComputed = computed + ev.Written()
			percent := float32(float64(newComputed) / (float64(total) / float64(100)))
			log.Printf("on EventWritten: %v/%v bytes written(%.2f%%)", newComputed, total, percent)

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
			newComputed = computed + ev.Written()
			percent := float32(float64(newComputed) / (float64(total) / float64(100)))
			log.Printf("on EventOK: %v/%v bytes written(%.2f%%)", newComputed, total, percent)

			// Get the final SHA-256 checksum of the remote file.
			checksums := h2.Checksums()
			fmt.Printf("SHA-256:\n%x\n", checksums["SHA-256"])

			// Verify the SHA-256 checksum.
			matched, alg := h2.Match("10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb")
			fmt.Printf("matched: %v, matched hash algorithm: %v", matched, alg)
		}
	}

	// The event channel will be closed after:
	// (1). iocopy.EventError received.
	// (2). iocopy.EventStop received.
	// (3). iocopy.EventOK received.
	// The for-range loop exits when the channel is closed.
	log.Printf("Stage 2: h2.Start() gouroutine exited and the event channel is closed")

	// Output:
	// SHA-256:
	// 10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb
	// matched: true, matched hash algorithm: SHA-256
}

func ExampleFromFile() {
	// URL of Ubuntu release.
	// SHA-256:
	// 10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb
	downloadURL := "https://www.releases.ubuntu.com/jammy/ubuntu-22.04.1-live-server-amd64.iso"

	// Download the file.
	file := filepath.Join(os.TempDir(), "ubuntu-22.04.1-live-server-amd64.iso")
	log.Printf("file: %v", file)

	f, err := os.Create(file)
	if err != nil {
		log.Printf("os.Create() error: %v", err)
		return
	}
	// Close and delete the temp file.
	defer func() {
		f.Close()
		os.Remove(file)
	}()

	// Get remote file size.
	total, _, err := httputil.ContentLength(downloadURL)
	if err != nil {
		log.Printf("httputil.ContentLength() error: %v", err)
		return
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		log.Printf("http.Get() error: %v", err)
		return
	}
	defer resp.Body.Close()

	// Use iocopy package to make a asynchronous download.
	ch := iocopy.Start(
		// Context
		context.Background(),
		// Dst
		f,
		// Src
		resp.Body,
		// Buffer
		32*1024,
		// Interval
		800*time.Millisecond)

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
			return

		case *iocopy.EventOK:
			// IO copy succeeded.
			// Get the total count of written bytes.
			n := ev.Written()
			percent := float32(float64(n) / (float64(total) / float64(100)))
			log.Printf("on EventOK: %v/%v bytes written(%.2f%%)", n, total, percent)

			log.Printf("file downloaded successfully.")
		}
	}

	// The event channel will be closed after:
	// (1). iocopy.EventError received.
	// (2). iocopy.EventStop received.
	// (3). iocopy.EventOK received.
	// The for-range loop exits when the channel is closed.
	log.Printf("IO copy gouroutine exited and the event channel is closed")

	// Create a hasher from file.
	h, total, _ := hasher.FromFile(file, "MD5", "SHA-256")

	// Close the hasher after use.
	defer h.Close()

	// Start a worker goroutine to compute hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch = h.Start(
		// Context
		context.Background(),
		// Buffer size
		16*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

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
			return

		case *iocopy.EventOK:
			// IO copy succeeded.
			// Get the total count of written bytes.
			n := ev.Written()
			percent := float32(float64(n) / (float64(total) / float64(100)))
			log.Printf("on EventOK: %v/%v bytes written(%.2f%%)", n, total, percent)

			// Get the final SHA-256 checksum of the remote file.
			checksums := h.Checksums()
			fmt.Printf("SHA-256:\n%x\n", checksums["SHA-256"])

			// Verify the SHA-256 checksum.
			matched, alg := h.Match("10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb")
			fmt.Printf("matched: %v, matched hash algorithm: %v", matched, alg)
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
	// matched: true, matched hash algorithm: SHA-256
}

func ExampleFromFileWithStates() {
	// states is used to save hashes states.
	var states = make(map[string][]byte)

	// computed is the number of bytes has been written / hashed.
	var computed int64 = 0

	// URL of Ubuntu release.
	// SHA-256:
	// 10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb
	downloadURL := "https://www.releases.ubuntu.com/jammy/ubuntu-22.04.1-live-server-amd64.iso"

	// Download the file.
	file := filepath.Join(os.TempDir(), "ubuntu-22.04.1-live-server-amd64.iso")
	log.Printf("file: %v", file)

	f, err := os.Create(file)
	if err != nil {
		log.Printf("os.Create() error: %v", err)
		return
	}
	// Close and delete the temp file.
	defer func() {
		f.Close()
		os.Remove(file)
	}()

	// Get remote file size.
	total, _, err := httputil.ContentLength(downloadURL)
	if err != nil {
		log.Printf("httputil.ContentLength() error: %v", err)
		return
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		log.Printf("http.Get() error: %v", err)
		return
	}
	defer resp.Body.Close()

	// Use iocopy package to make a asynchronous download.
	ch := iocopy.Start(
		// Context
		context.Background(),
		// Dst
		f,
		// Src
		resp.Body,
		// Buffer
		32*1024,
		// Interval
		800*time.Millisecond)

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
			return

		case *iocopy.EventOK:
			// IO copy succeeded.
			// Get the total count of written bytes.
			n := ev.Written()
			percent := float32(float64(n) / (float64(total) / float64(100)))
			log.Printf("on EventOK: %v/%v bytes written(%.2f%%)", n, total, percent)

			log.Printf("file downloaded successfully.")
		}
	}

	// The event channel will be closed after:
	// (1). iocopy.EventError received.
	// (2). iocopy.EventStop received.
	// (3). iocopy.EventOK received.
	// The for-range loop exits when the channel is closed.
	log.Printf("IO copy gouroutine exited and the event channel is closed")

	// Stage 1.
	// Create a hasher from file.
	h1, total, _ := hasher.FromFile(file, "MD5", "SHA-256")

	// Close the hasher after use.
	defer h1.Close()

	// create a context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a worker goroutine to compute hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch = h1.Start(
		// Context
		ctx,
		// Buffer size
		16*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

	// Read the events from the channel.
	for event := range ch {
		switch ev := event.(type) {
		case *iocopy.EventWritten:
			// n bytes have been written successfully.
			// Get the count of bytes.
			computed = ev.Written()
			percent := float32(float64(computed) / (float64(total) / float64(100)))
			log.Printf("on EventWritten: %v/%v bytes written(%.2f%%)", computed, total, percent)
			// Stop computing hash when percent > 50%.
			if percent > 50 {
				cancel()
			}

		case *iocopy.EventStop:
			// Context is canceled or
			// context's deadline exceeded.
			log.Printf("on EventStop: %v", ev.Err())

			// Save the number of computed bytes.
			computed = ev.Written()

			// Save the hashes states.
			states, _ = h1.States()

		case *iocopy.EventError:
			// an error occured.
			// Get the error.
			log.Printf("on EventError: %v", ev.Err())

		case *iocopy.EventOK:
		}
	}

	// The event channel will be closed after:
	// (1). iocopy.EventError received.
	// (2). iocopy.EventStop received.
	// (3). iocopy.EventOK received.
	// The for-range loop exits when the channel is closed.
	log.Printf("Stage 1: h1.Start() gouroutine exited and the event channel is closed")

	// Stage 2.
	// Create a hasher from file with number of computed bytes and
	// saved states to continue to compute hashes.
	h2, total, _ := hasher.FromFileWithStates(
		// File path
		file,
		// Number of computed bytes
		computed,
		// States of hashes
		states)

	// Close the hasher after use.
	defer h2.Close()

	// Start a worker goroutine to compute hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch = h2.Start(
		// Context
		context.Background(),
		// Buffer size
		16*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

	newComputed := int64(0)

	// Read the events from the channel.
	for event := range ch {
		switch ev := event.(type) {
		case *iocopy.EventWritten:
			// n bytes have been written successfully.
			// Get the count of bytes.
			newComputed = computed + ev.Written()
			percent := float32(float64(newComputed) / (float64(total) / float64(100)))
			log.Printf("on EventWritten: %v/%v bytes written(%.2f%%)", newComputed, total, percent)

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
			newComputed = computed + ev.Written()
			percent := float32(float64(newComputed) / (float64(total) / float64(100)))
			log.Printf("on EventOK: %v/%v bytes written(%.2f%%)", newComputed, total, percent)

			// Get the final SHA-256 checksum of the remote file.
			checksums := h2.Checksums()
			fmt.Printf("SHA-256:\n%x\n", checksums["SHA-256"])

			// Verify the SHA-256 checksum.
			matched, alg := h2.Match("10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb")
			fmt.Printf("matched: %v, matched hash algorithm: %v", matched, alg)
		}
	}

	// The event channel will be closed after:
	// (1). iocopy.EventError received.
	// (2). iocopy.EventStop received.
	// (3). iocopy.EventOK received.
	// The for-range loop exits when the channel is closed.
	log.Printf("Stage 2: h2.Start() gouroutine exited and the event channel is closed")

	// Output:
	// SHA-256:
	// 10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb
	// matched: true, matched hash algorithm: SHA-256
}

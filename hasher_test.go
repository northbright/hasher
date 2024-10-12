package hasher_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/northbright/hasher"
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

/*
// eventHandler reads the events from channel and block caller's go-routine.
// It updates and reports the progress of computing hashes.
// It returns the number of the computed bytes and the saved states after
// the channel is closed.
// The event channel will be closed after:
// (1). iocopy.EventError received.
// (2). iocopy.EventStop received.
// (3). iocopy.EventOK received.
func eventHandler(
	h *hasher.Hasher,
	total int64,
	previousComputed int64,
	expectedSHA256 string,
	ch <-chan iocopy.Event) (computed int64, states map[string][]byte) {
	states = make(map[string][]byte)

	// Read the events from the channel.
	for event := range ch {
		switch ev := event.(type) {
		case *iocopy.EventWritten:
			// n bytes have been written successfully.
			// Get the count of bytes.
			computed = previousComputed + ev.Written()
			percent := float32(float64(computed) / (float64(total) / float64(100)))
			log.Printf("on EventWritten: %v/%v bytes written(%.2f%%)", computed, total, percent)

		case *iocopy.EventStop:
			// Context is canceled or
			// context's deadline exceeded.

			// Save the number of computed bytes and states.
			computed = previousComputed + ev.Written()
			states, _ = h.States()

			log.Printf("on EventStop: %v, computed: %v", ev.Err(), computed)

		case *iocopy.EventError:
			// an error occured.
			// Get the error.
			log.Printf("on EventError: %v", ev.Err())

		case *iocopy.EventOK:
			// Get the total count of written bytes.
			computed = previousComputed + ev.Written()
			percent := float32(float64(computed) / (float64(total) / float64(100)))
			log.Printf("on EventOK: %v/%v bytes written(%.2f%%)", computed, total, percent)

			// Save the states.
			states, _ = h.States()

			// Get the final SHA-256 checksum of the remote file.
			checksums := h.Checksums()
			fmt.Printf("SHA-256:\n%x\n", checksums["SHA-256"])

			// Verify the SHA-256 checksum.
			matched, alg := h.Match(expectedSHA256)
			fmt.Printf("matched: %v, matched hash algorithm: %v", matched, alg)
		}
	}

	return computed, states
}

func ExampleFromStrings() {
	// Example of computing strings hash.
	// Compute the SHA-256 hash of the strings in offical example:
	// https://pkg.go.dev/hash#example-package-BinaryMarshaler
	const (
		input1 = "The tunneling gopher digs downwards, "
		input2 = "unaware of what he will find."
	)

	// Specify hash algorithms.
	// Currently, it supports: "MD5", "SHA-1", "SHA-256", "SHA-512", "CRC-32".
	// Call SupportedHashAlgs to get all available hash algorithms.
	algs := []string{"MD5", "SHA-256", "CRC-32"}

	// Create a hasher with given hash algorithms.
	h, total, _ := hasher.FromStrings(
		// String slice
		[]string{input1, input2},
		// Hash algorithms
		algs)

	// Close the hasher after use.
	defer h.Close()

	// Compute the hashes of the strings.
	checksums, n, _ := h.Compute(context.Background())

	// Show the checksums and count of written bytes.
	for alg, checksum := range checksums {
		log.Printf("%s: %x", alg, checksum)
	}
	log.Printf("%d bytes written(total: %v)", n, total)

	// Output SHA-256 checksum.
	fmt.Printf("%x", checksums["SHA-256"])

	// Output:
	// 57d51a066f3a39942649cd9a76c77e97ceab246756ff3888659e6aa5a07f4a52
}

func ExampleFromUrl() {
	// URL of the remote file.
	downloadURL := "https://golang.google.cn/dl/go1.20.1.darwin-amd64.pkg"
	expectedSHA256 := "9e2f2a4031b215922aa21a3695e30bbfa1f7707597834287415dbc862c6a3251"

	// Specify hash algorithms.
	// Currently, it supports: "MD5", "SHA-1", "SHA-256", "SHA-512", "CRC-32".
	// Call SupportedHashAlgs to get all available hash algorithms.
	algs := []string{"MD5", "SHA-256"}

	// Create a hasher from the URL.
	// The total content length of the URL will be returned if possible.
	h, total, err := hasher.FromUrl(downloadURL, algs)
	if err != nil {
		log.Printf("FromUrl() error: %v", err)
		return
	}

	// Close the hasher after use.
	defer h.Close()

	// Start a worker goroutine to compute the hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch := h.Start(
		// Context
		context.Background(),
		// Buffer size
		32*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

	// Read the events from the events and block current go-routine.
	eventHandler(
		// Hasher
		h,
		// Number of total bytes to compute
		total,
		// Number of previous computed bytes
		0,
		// Expected SHA-256 Checksum.
		expectedSHA256,
		// Event Channel
		ch)

	log.Printf("h.Start() gouroutine exited and the event channel is closed")

	// Output:
	// SHA-256:
	// 9e2f2a4031b215922aa21a3695e30bbfa1f7707597834287415dbc862c6a3251
	// matched: true, matched hash algorithm: SHA-256
}

func ExampleFromUrlWithStates() {
	// URL of the remote file.
	downloadURL := "https://golang.google.cn/dl/go1.20.1.darwin-amd64.pkg"
	expectedSHA256 := "9e2f2a4031b215922aa21a3695e30bbfa1f7707597834287415dbc862c6a3251"

	// Specify hash algorithms.
	// Currently, it supports: "MD5", "SHA-1", "SHA-256", "SHA-512", "CRC-32".
	// Call SupportedHashAlgs to get all available hash algorithms.
	algs := []string{"MD5", "SHA-256"}

	// Stage 1.
	// Create a hasher from the URL.
	// The total content length of the URL will be returned if possible.
	h1, total, err := hasher.FromUrl(downloadURL, algs)
	if err != nil {
		log.Printf("FromUrl() error: %v", err)
		return
	}

	// Close the hasher after use.
	defer h1.Close()

	// create a context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a worker goroutine to compute the hashes of content of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch := h1.Start(
		// Context
		ctx,
		// Buffer size
		32*1024*1024,
		// Interval to report written bytes
		200*time.Millisecond)

	// Emulate: user cancelation.
	// Set the timeout.
	go func() {
		<-time.After(500 * time.Millisecond)
		cancel()
	}()

	// Read the events from the events and block current go-routine.
	computed, states := eventHandler(
		// Hasher
		h1,
		// Number of total bytes to compute
		total,
		// Number of previous computed bytes
		0,
		// Expected SHA-256 Checksum.
		expectedSHA256,
		// Event Channel
		ch)

	log.Printf("Stage 1: h1.Start() gouroutine exited and the event channel is closed. Computed: %v", computed)

	// Check if it's all done at stage 1.
	// No need to go to next stages.
	if computed == total {
		return
	}

	// Stage 2.
	// Emulate the user case: pause / resume the computing without
	// exiting the program.
	// The hasher(h1) is still in memory.
	// Re-use the hasher(h1) without loading the states.

	// create a context.
	ctx, cancel = context.WithCancel(context.Background())

	// Re-use previous hasher and continue computing.
	ch = h1.Start(
		// Context
		ctx,
		// Buffer size
		32*1024*1024,
		// Interval to report written bytes
		200*time.Millisecond)

	// Emulate: user cancelation.
	// Set the timeout.
	go func() {
		<-time.After(500 * time.Millisecond)
		cancel()
	}()

	// Read the events from the events and block current go-routine.
	computed, states = eventHandler(
		// Hasher
		h1,
		// Number of total bytes to compute
		total,
		// Number of previous computed bytes
		computed,
		// Expected SHA-256 Checksum.
		expectedSHA256,
		// Event Channel
		ch)

	log.Printf("Stage 2: h1.Start() gouroutine exited and the event channel is closed. Computed: %v", computed)

	// Check if it's all done at stage 2.
	// No need to go to next stages.
	if computed == total {
		return
	}

	// Stage 3.
	// Emulate the user case: exit and restart the program.
	// The hasher's memory is freed.
	// Use saved states to continue the computing.

	// Create a new hasher from the URL with saved states.
	h2, total, err := hasher.FromUrlWithStates(
		// URL
		downloadURL,
		// Number of computed bytes
		computed,
		// States of hashes
		states)

	if err != nil {
		log.Printf("FromUrlWithStates() error: %v", err)
		return
	}

	// Close the hasher after use.
	defer h2.Close()

	// Start a worker goroutine to compute the hashes of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch = h2.Start(
		// Context
		context.Background(),
		// Buffer size
		32*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

	// Read the events from the events and block current go-routine.
	computed, states = eventHandler(
		// Hasher
		h2,
		// Number of total bytes to compute
		total,
		// Number of previous computed bytes
		computed,
		// Expected SHA-256 Checksum.
		expectedSHA256,
		// Event Channel
		ch)

	log.Printf("Stage 3: h2.Start() gouroutine exited and the event channel is closed. Computed: %v", computed)

	// Output:
	// SHA-256:
	// 9e2f2a4031b215922aa21a3695e30bbfa1f7707597834287415dbc862c6a3251
	// matched: true, matched hash algorithm: SHA-256
}

func download(downloadURL, file string) (int64, error) {
	f, err := os.Create(file)
	if err != nil {
		log.Printf("os.Create() error: %v", err)
		return 0, err
	}
	// Close and delete the temp file.
	defer func() {
		f.Close()
	}()

	// Get remote file size.
	total, _, err := httputil.ContentLength(downloadURL)
	if err != nil {
		log.Printf("httputil.ContentLength() error: %v", err)
		return 0, err
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		log.Printf("http.Get() error: %v", err)
		return 0, err
	}
	defer resp.Body.Close()

	// Download the file.
	copied, err := io.Copy(f, resp.Body)
	if err != nil {
		log.Printf("io.Copy() error: %v", err)
		return 0, err
	}

	if copied != total {
		return 0, fmt.Errorf("downloaded size != total size")
	}

	return total, nil
}

func ExampleFromFile() {
	// URL of the remote file.
	downloadURL := "https://golang.google.cn/dl/go1.20.1.darwin-amd64.pkg"
	expectedSHA256 := "9e2f2a4031b215922aa21a3695e30bbfa1f7707597834287415dbc862c6a3251"

	// Get temp file name.
	file := filepath.Join(os.TempDir(), filepath.Base(downloadURL))
	log.Printf("file: %v", file)
	defer os.Remove(file)

	// Download the file.
	total, err := download(downloadURL, file)
	if err != nil {
		log.Printf("download() error: %v", err)
		return
	}

	log.Printf("download file successfully, total: %v bytes", total)

	// Specify hash algorithms.
	// Currently, it supports: "MD5", "SHA-1", "SHA-256", "SHA-512", "CRC-32".
	// Call SupportedHashAlgs to get all available hash algorithms.
	algs := []string{"MD5", "SHA-256"}

	// Create a hasher from the file.
	h, total, err := hasher.FromFile(file, algs)
	if err != nil {
		log.Printf("FromFile() error: %v", err)
		return
	}

	// Close the hasher after use.
	defer h.Close()

	// Start a worker goroutine to compute the hashes of the URL.
	// It will return a channel used to read the events(iocopy.Event).
	ch := h.Start(
		// Context
		context.Background(),
		// Buffer size
		32*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

	// Read the events from the events and block current go-routine.
	eventHandler(
		// Hasher
		h,
		// Number of total bytes to compute
		total,
		// Number of previous computed bytes
		0,
		// Expected SHA-256 Checksum.
		expectedSHA256,
		// Event Channel
		ch)

	log.Printf("h.Start() gouroutine exited and the event channel is closed")

	// Output:
	// SHA-256:
	// 9e2f2a4031b215922aa21a3695e30bbfa1f7707597834287415dbc862c6a3251
	// matched: true, matched hash algorithm: SHA-256
}

func ExampleFromFileWithStates() {
	// URL of the remote file.
	downloadURL := "https://golang.google.cn/dl/go1.20.1.darwin-amd64.pkg"
	expectedSHA256 := "9e2f2a4031b215922aa21a3695e30bbfa1f7707597834287415dbc862c6a3251"

	// Get temp file name.
	file := filepath.Join(os.TempDir(), filepath.Base(downloadURL))
	log.Printf("file: %v", file)
	defer os.Remove(file)

	// Download the file.
	total, err := download(downloadURL, file)
	if err != nil {
		log.Printf("download() error: %v", err)
		return
	}

	log.Printf("download file successfully, total: %v bytes", total)

	// Specify hash algorithms.
	// Currently, it supports: "MD5", "SHA-1", "SHA-256", "SHA-512", "CRC-32".
	// Call SupportedHashAlgs to get all available hash algorithms.
	algs := []string{"MD5", "SHA-256"}

	// Stage 1.
	// Create a hasher from the file.
	h1, total, err := hasher.FromFile(file, algs)
	if err != nil {
		log.Printf("FromFile() error: %v", err)
		return
	}

	// Close the hasher after use.
	defer h1.Close()

	// create a context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a worker goroutine to compute the hashes of the file.
	// It will return a channel used to read the events(iocopy.Event).
	ch := h1.Start(
		// Context
		ctx,
		// Buffer size
		32*1024*1024,
		// Interval to report written bytes
		200*time.Millisecond)

	// Emulate: user cancelation.
	// Set the timeout.
	go func() {
		<-time.After(100 * time.Millisecond)
		cancel()
	}()

	// Read the events from the events and block current go-routine.
	computed, states := eventHandler(
		// Hasher
		h1,
		// Number of total bytes to compute
		total,
		// Number of previous computed bytes
		0,
		// Expected SHA-256 Checksum.
		expectedSHA256,
		// Event Channel
		ch)

	log.Printf("Stage 1: h1.Start() gouroutine exited and the event channel is closed. Computed: %v", computed)

	// Check if it's all done at stage 1.
	// No need to go to next stages.
	if computed == total {
		return
	}

	// Stage 2.
	// Emulate the user case: pause / resume the computing without
	// exiting the program.
	// The hasher(h1) is still in memory.
	// Re-use the hasher(h1) without loading the states.

	// create a context.
	ctx, cancel = context.WithCancel(context.Background())

	// Re-use previous hasher and continue computing.
	ch = h1.Start(
		// Context
		ctx,
		// Buffer size
		32*1024*1024,
		// Interval to report written bytes
		50*time.Millisecond)

	// Emulate: user cancelation.
	// Set the timeout.
	go func() {
		<-time.After(80 * time.Millisecond)
		cancel()
	}()

	// Read the events from the events and block current go-routine.
	computed, states = eventHandler(
		// Hasher
		h1,
		// Number of total bytes to compute
		total,
		// Number of previous computed bytes
		computed,
		// Expected SHA-256 Checksum.
		expectedSHA256,
		// Event Channel
		ch)

	log.Printf("Stage 2: h1.Start() gouroutine exited and the event channel is closed. Computed: %v", computed)

	// Check if it's all done at stage 2.
	// No need to go to next stages.
	if computed == total {
		return
	}

	// Stage 3.
	// Emulate the user case: exit the program and restart the program.
	// The hasher's memory is freed.
	// Use saved states to continue computing.

	// Create a new hasher from the file with saved states.
	h2, total, err := hasher.FromFileWithStates(
		// File
		file,
		// Number of computed bytes
		computed,
		// States of hashes
		states)

	if err != nil {
		log.Printf("FromUrlWithStates() error: %v", err)
		return
	}

	// Close the hasher after use.
	defer h2.Close()

	// Start a worker goroutine to compute the hashes of the file.
	// It will return a channel used to read the events(iocopy.Event).
	ch = h2.Start(
		// Context
		context.Background(),
		// Buffer size
		32*1024*1024,
		// Interval to report written bytes
		500*time.Millisecond)

	// Read the events from the events and block current go-routine.
	computed, states = eventHandler(
		// Hasher
		h2,
		// Number of total bytes to compute
		total,
		// Number of previous computed bytes
		computed,
		// Expected SHA-256 Checksum.
		expectedSHA256,
		// Event Channel
		ch)

	log.Printf("Stage 3: h2.Start() gouroutine exited and the event channel is closed. Computed: %v", computed)

	// Output:
	// SHA-256:
	// 9e2f2a4031b215922aa21a3695e30bbfa1f7707597834287415dbc862c6a3251
	// matched: true, matched hash algorithm: SHA-256
}
*/

func ExampleChecksums() {
	// This example uses hasher.Checksums to read stream from a remote file,
	// and compute its SHA-256 checksum.
	// It uses a timeout context to emulate user cancelation to stop the calculation.
	// Then it calls hasher.Checksums again to resume the calculation.

	// SHA-256: dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
	url := "https://golang.google.cn/dl/go1.23.1.darwin-amd64.pkg"

	// Get response body(io.Reader) of the remote file.
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("http.Get() error: %v, url: %v", err, url)
	}
	defer resp.Body.Close()

	// Try to get size of the file.
	size := int64(-1)
	str := resp.Header.Get("Content-Length")
	if str != "" {
		size, _ = strconv.ParseInt(str, 10, 64)
	}

	// Use a timeout to emulate user's cancelation.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*200)
	defer cancel()

	n, states, err := hasher.Checksums(
		// context.Context.
		ctx,
		// io.Reader
		resp.Body,
		// Total Size.
		size,
		// Option to set hash algorithms.
		hasher.Algs([]string{"SHA-256"}),
		// Option to set OnDownloadFunc to report progress.
		hasher.OnHash(func(total, prev, current int64, percent float32) {
			log.Printf("%v / %v(%.2f%%) calculated", prev+current, total, percent)

		}),
	)

	if err != nil {
		if err != context.Canceled && err != context.DeadlineExceeded {
			log.Printf("hasher.Checksums() error: %v", err)
			return
		} else {
			log.Printf("calculation stopped by user, bytes hashed: %v, states: %v\n", n, states)
		}
	} else {
		log.Printf("hasher.Checksums() OK")
		fmt.Printf("%x", states["SHA-256"])
	}

	// Call hasher.Checksums again to resume previous calculation.
	n, checksums, err := hasher.Checksums(
		// context.Context.
		context.Background(),
		// io.Reader.
		// The offset of the reader should be corresponding to the previous states.
		resp.Body,
		// Total Size.
		size,
		// States to resume previous calculation.
		hasher.States(n, states),
		// Option to set hash algorithms.
		hasher.Algs([]string{"SHA-256"}),
		// Option to set OnDownloadFunc to report progress.
		hasher.OnHash(func(total, prev, current int64, percent float32) {
			log.Printf("%v / %v(%.2f%%) calculated", prev+current, total, percent)

		}),
	)

	if err != nil {
		if err != context.Canceled && err != context.DeadlineExceeded {
			log.Printf("hasher.Checksums() error: %v", err)
			return
		} else {
			log.Printf("calculation stopped by user, bytes hashed: %v, states: %v\n", n, states)
		}
	} else {
		log.Printf("hasher.Checksums() OK")
		fmt.Printf("%x", checksums["SHA-256"])
	}

	// Output:
	// dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
}

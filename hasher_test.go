package hasher_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/northbright/hasher"
)

func ExampleHasher_Start() {
	hashFuncs := []string{
		"MD5",
		"SHA-1",
		"SHA-256",
	}
	bufferSize := int64(16 * 1024 * 1024)

	h := hasher.New(hashFuncs, bufferSize)

	// Test 1
	// Read a string and compute hashes.
	str := "Hello World!"
	ctx := context.Background()
	// Start computing the hash of the string.
	ch := h.Start(ctx, strings.NewReader(str), 0, 0, nil)

	for event := range ch {
		switch ev := event.(type) {
		case *hasher.EventError:
			log.Printf("on error: %v", ev.Err())
			return
		case *hasher.EventStop:
			log.Printf("on stopped:\ncomputed: %v, states: %v", ev.Computed(), ev.States())
		case *hasher.EventOK:
			log.Printf("on ok:\ncomputed: %v\nchecksums:\n", ev.Computed())
			for name, checksum := range ev.Checksums() {
				log.Printf("%s: %X", name, checksum)
			}
		}
	}

	// Test 2
	// Read Golang package on remote and compute hashes.
	// See: https://golang.google.cn/dl/
	goPkgURL := "https://golang.google.cn/dl/go1.19.3.darwin-amd64.pkg"
	goPkgSHA256 := `a4941f5b09c43adeed13aaf435003a1e8852977037b3e6628d11047b087c4c66`

	res, err := http.Get(goPkgURL)
	if err != nil {
		log.Printf("http.Get() error: %v", err)
		return
	}

	if res.StatusCode != 200 {
		log.Printf("status code is NOT 200: %v", res.StatusCode)
		return
	}

	log.Printf("res.ContentLength: %v", res.ContentLength)
	fileSize := res.ContentLength

	ch = h.Start(ctx, res.Body, fileSize, time.Millisecond*800, nil)
	defer res.Body.Close()

	for event := range ch {
		switch ev := event.(type) {
		case *hasher.EventError:
			log.Printf("on error: %v", ev.Err())
			return
		case *hasher.EventProgress:
			log.Printf("on progress: %.2f%%", ev.Percent())
		case *hasher.EventStop:
			log.Printf("on stopped:\ncomputed: %v, states: %v", ev.Computed(), ev.States())
		case *hasher.EventOK:
			log.Printf("on ok:\ncomputed: %v\nchecksums:\n", ev.Computed())
			for name, checksum := range ev.Checksums() {
				if name == "SHA-256" {
					checksumStr := fmt.Sprintf("%x", checksum)
					if strings.Compare(goPkgSHA256, checksumStr) != 0 {
						log.Printf("SHA-256 checksums are different: original: %v, computed: %v", goPkgSHA256, checksumStr)
						return
					} else {
						// Checksum is correct.
						log.Printf("SHA-256 checksum is verified")
					}
				}

				log.Printf("%s: %X", name, checksum)
			}
		}
	}

	// Test 3
	// The same as Test 2:
	// Read Golang package on remote and compute hashes.
	// See: https://golang.google.cn/dl/
	// But use progress bar to show progress
	// instead of processing progress events.
	// See https://github.com/cheggaaa/pb for more info.
	goPkgURL = "https://golang.google.cn/dl/go1.19.3.darwin-amd64.pkg"
	goPkgSHA256 = `a4941f5b09c43adeed13aaf435003a1e8852977037b3e6628d11047b087c4c66`

	res, err = http.Get(goPkgURL)
	if err != nil {
		log.Printf("http.Get() error: %v", err)
		return
	}

	if res.StatusCode != 200 {
		log.Printf("status code is NOT 200: %v", res.StatusCode)
		return
	}

	log.Printf("res.ContentLength: %v", res.ContentLength)
	fileSize = res.ContentLength

	// Create a progress bar with default preset.
	bar := pb.Default.Start64(fileSize)

	// pb.Reader implements the io.Reader interface.
	// Create a proxy reader to make the progress bar get the number
	// of bytes read.
	barReader := bar.NewProxyReader(res.Body)

	// Stop the progress bar after use.
	defer bar.Finish()

	ch = h.Start(ctx, barReader, fileSize, time.Millisecond*800, nil)
	defer res.Body.Close()

	for event := range ch {
		switch ev := event.(type) {
		case *hasher.EventError:
			log.Printf("on error: %v", ev.Err())
			return
		case *hasher.EventStop:
			log.Printf("on stopped:\ncomputed: %v, states: %v", ev.Computed(), ev.States())
		case *hasher.EventOK:
			// Stop progressbar printing.
			bar.Finish()

			log.Printf("on ok:\ncomputed: %v\nchecksums:\n", ev.Computed())
			for name, checksum := range ev.Checksums() {
				if name == "SHA-256" {
					checksumStr := fmt.Sprintf("%x", checksum)
					if strings.Compare(goPkgSHA256, checksumStr) != 0 {
						log.Printf("SHA-256 checksums are different: original: %v, computed: %v", goPkgSHA256, checksumStr)
						return
					} else {
						// Checksum is correct.
						log.Printf("SHA-256 checksum is verified")
					}
				}

				log.Printf("%s: %X", name, checksum)
			}
		}
	}

	// Output:
}

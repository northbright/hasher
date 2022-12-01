package hasher_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
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
	ch := h.Start(ctx, strings.NewReader(str), 0, 0)

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

	resp1, err := http.Get(goPkgURL)
	if err != nil {
		log.Printf("http.Get() error: %v", err)
		return
	}

	if resp1.StatusCode != 200 {
		log.Printf("status code is NOT 200: %v", resp1.StatusCode)
		return
	}

	log.Printf("resp1.ContentLength: %v", resp1.ContentLength)
	fileSize := resp1.ContentLength

	// Start reading and hashing.
	ch = h.Start(ctx, resp1.Body, fileSize, time.Millisecond*800)
	defer resp1.Body.Close()

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
					goPkgSHA256 := `a4941f5b09c43adeed13aaf435003a1e8852977037b3e6628d11047b087c4c66`
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

	resp2, err := http.Get(goPkgURL)
	if err != nil {
		log.Printf("http.Get() error: %v", err)
		return
	}

	if resp2.StatusCode != 200 {
		log.Printf("status code is NOT 200: %v", resp2.StatusCode)
		return
	}

	log.Printf("resp2.ContentLength: %v", resp2.ContentLength)
	fileSize = resp2.ContentLength

	// Create a progress bar with default preset.
	bar := pb.Default.Start64(fileSize)

	// pb.Reader implements the io.Reader interface.
	// Create a proxy reader to make the progress bar get the number
	// of bytes read.
	barReader := bar.NewProxyReader(resp2.Body)

	// Stop the progress bar after use.
	defer bar.Finish()

	// Start reading and hashing.
	ch = h.Start(ctx, barReader, fileSize, time.Millisecond*800)
	defer resp2.Body.Close()

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
					goPkgSHA256 := `a4941f5b09c43adeed13aaf435003a1e8852977037b3e6628d11047b087c4c66`
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

func ExampleHasher_StartWithStates() {
	var err error

	hashFuncs := []string{
		"MD5",
		"SHA-1",
		"SHA-256",
	}
	bufferSize := int64(16 * 1024 * 1024)

	h := hasher.New(hashFuncs, bufferSize)

	// Read Golang package on remote and compute hashes.
	// See: https://golang.google.cn/dl/
	// Stop reading / hashing and save the states when the progress > 50.
	// Then continue to read / hash with saved states.

	// Step 1
	// Read and hash the file for the first time.
	goPkgURL := "https://golang.google.cn/dl/go1.19.3.darwin-amd64.pkg"

	resp1, err := http.Get(goPkgURL)
	if err != nil {
		log.Printf("http.Get() error: %v", err)
		return
	}

	if resp1.StatusCode != 200 {
		log.Printf("status code is NOT 200: %v", resp1.StatusCode)
		return
	}

	log.Printf("resp1.ContentLength: %v", resp1.ContentLength)
	fileSize := resp1.ContentLength

	// Create a progress bar with default preset.
	bar := pb.Default.Start64(fileSize)

	// pb.Reader implements the io.Reader interface.
	// Create a proxy reader to make the progress bar get the number
	// of bytes read.
	barReader := bar.NewProxyReader(resp1.Body)

	// Stop the progress bar after use.
	defer bar.Finish()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := h.Start(ctx, barReader, fileSize, time.Millisecond*100)
	defer resp1.Body.Close()

	var (
		computed int64 = 0
		states         = make(map[string][]byte)
	)

	for event := range ch {
		switch ev := event.(type) {
		case *hasher.EventError:
			log.Printf("on error: %v", ev.Err())
			return
		case *hasher.EventStop:
			// Get the number of computed bytes and saved states.
			computed = ev.Computed()
			states = ev.States()
			log.Printf("on stopped:\ncomputed: %v, states: %v", computed, states)
		case *hasher.EventProgress:
			percent := ev.Percent()
			if percent >= 50 {
				// Cancel reading / hashing if percent > 50
				bar.Finish()
				cancel()
			}
		}
	}

	// Step 2
	// Continue to read / hash the file with saved states.
	client := http.Client{}
	req, _ := http.NewRequest("GET", goPkgURL, nil)

	// Set request range.
	bytesRange := fmt.Sprintf("bytes=%d-%d", computed, fileSize-1)
	log.Printf("request range: %v", bytesRange)
	req.Header.Add("range", bytesRange)

	// Do HTTP request.
	resp2, err := client.Do(req)
	if err != nil {
		log.Printf("do HTTP request error: %v", err)
		return
	}

	// Check if status code is 206.
	if resp2.StatusCode != 206 {
		log.Printf("status code is %v(NOT 206)", resp2.StatusCode)
		return
	}

	// Get total bytes to read from Content-Range.
	contentRange := resp2.Header.Get("Content-Range")
	// Content-Range: bytes xx-xx/xx
	log.Printf("Content-Range: %v", contentRange)

	contentRange = strings.TrimLeft(contentRange, "bytes ")
	log.Printf("after trim: %v", contentRange)

	s := strings.Split(contentRange, "/")
	if len(s) != 2 {
		log.Printf("failed to split Content-Range(/)")
		return
	}

	s = strings.Split(s[0], "-")
	if len(s) != 2 {
		log.Printf("failed to split Content-Range(-)")
		return
	}

	log.Printf("s: %v", s)
	start, _ := strconv.ParseInt(s[0], 10, 64)
	end, _ := strconv.ParseInt(s[1], 10, 64)

	// Both start and end position are inclusive.
	total := end - start + 1
	log.Printf("total = end(%v) - start(%v) + 1 = %v bytes need to continue to read / hash", end, start, total)

	// Create a progress bar with default preset.
	bar = pb.Default.Start64(total)

	// pb.Reader implements the io.Reader interface.
	// Create a proxy reader to make the progress bar get the number
	// of bytes read.
	barReader = bar.NewProxyReader(resp2.Body)

	// Stop the progress bar after use.
	defer bar.Finish()

	ctx = context.Background()

	// Start reading at offset(content-range) and hashing with saved states.
	ch = h.StartWithStates(ctx, barReader, total, time.Millisecond*800, states)
	defer resp2.Body.Close()

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
					goPkgSHA256 := `a4941f5b09c43adeed13aaf435003a1e8852977037b3e6628d11047b087c4c66`
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

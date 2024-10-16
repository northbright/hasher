package hasher_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/northbright/download"
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

	log.Printf("hasher.Checksums() starts...")
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
			log.Printf("hasher.Checksums() stopped by user, bytes hashed: %v, states: %v\n", n, states)
		}
	} else {
		log.Printf("hasher.Checksums() OK")
		fmt.Printf("%x", states["SHA-256"])
	}

	// Call hasher.Checksums again to resume previous calculation.
	log.Printf("hasher.Checksums() starts again to resume calculation...")
	n, checksums, err := hasher.Checksums(
		// context.Context.
		context.Background(),
		// io.Reader.
		// The offset of the reader should be corresponding to the previous states.
		resp.Body,
		// Total Size.
		size,
		// Option to set states to resume previous calculation.
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
			log.Printf("hasher.Checksums() stopped by user, bytes hashed: %v, states: %v\n", n, states)
		}
	} else {
		log.Printf("hasher.Checksums() OK")
		fmt.Printf("%x", checksums["SHA-256"])
	}

	// Output:
	// dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
}

func ExampleFileChecksums() {
	// This example uses hasher.FileChecksums to compute its SHA-256 checksum.
	// It uses a timeout context to emulate user cancelation to stop the calculation.
	// Then it calls hasher.FileChecksums again to resume the calculation.

	// SHA-256: dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
	url := "https://golang.google.cn/dl/go1.23.1.darwin-amd64.pkg"
	dst := filepath.Join(os.TempDir(), "go1.23.1.darwin-amd64.pkg")

	// Download a remote file.
	log.Printf("download.Download() starts...\nurl: %v\ndst: %v", url, dst)
	n, err := download.Download(
		// Context.
		context.Background(),
		// URL to download.
		url,
		// Destination.
		dst,
		// Option to set OnDownloadFunc to report progress.
		download.OnDownload(func(total, prev, current int64, percent float32) {
			log.Printf("%v / %v(%.2f%%) downloaded", prev+current, total, percent)
		}),
	)

	if err != nil {
		if err != context.Canceled && err != context.DeadlineExceeded {
			log.Printf("download.Download() error: %v", err)
			return
		}
		log.Printf("download.Download() stopped, cause: %v. %v bytes downloaded", err, n)
	} else {
		log.Printf("download.Download() OK, %v bytes downloaded", n)
	}

	// Use a timeout to emulate user's cancelation.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
	defer cancel()

	log.Printf("hasher.FileChecksums() starts...\nFile name = %v", dst)
	n, states, err := hasher.FileChecksums(
		// context.Context.
		ctx,
		// File name.
		dst,
		// Option to set hash algorithms.
		hasher.Algs([]string{"SHA-256"}),
		// Option to set OnDownloadFunc to report progress.
		hasher.OnHash(func(total, prev, current int64, percent float32) {
			log.Printf("%v / %v(%.2f%%) calculated", prev+current, total, percent)

		}),
	)

	if err != nil {
		if err != context.Canceled && err != context.DeadlineExceeded {
			log.Printf("hasher.FileChecksums() error: %v", err)
			return
		} else {
			log.Printf("hasher.FileChecksums() stopped by user, bytes hashed: %v, states: %v\n", n, states)
		}
	} else {
		log.Printf("hasher.FileChecksums() OK")
		fmt.Printf("%x", states["SHA-256"])
	}

	// Call hasher.FileChecksums again to resume previous calculation.
	log.Printf("hasher.FileChecksums() starts again to resume calculation...\nFile name = %v", dst)
	n, checksums, err := hasher.FileChecksums(
		// context.Context.
		context.Background(),
		// File name.
		dst,
		// Option to set states to resume previous calculation.
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
			log.Printf("hasher.FileChecksums() error: %v", err)
			return
		} else {
			log.Printf("hasher.FileChecksums() stopped by user, bytes hashed: %v, states: %v\n", n, states)
		}
	} else {
		log.Printf("hasher.FileChecksums() OK")
		fmt.Printf("%x", checksums["SHA-256"])
	}

	// Output:
	// dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
}

func ExampleURLChecksums() {
	// This example uses hasher.URLChecksums to compute SHA-256 checksum of remote file.
	// It uses a timeout context to emulate user cancelation to stop the calculation.
	// Then it calls hasher.URLChecksums again to resume the calculation.

	// SHA-256: dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
	url := "https://golang.google.cn/dl/go1.23.1.darwin-amd64.pkg"

	// Use a timeout to emulate user's cancelation.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()

	log.Printf("hasher.URLChecksums() starts...\nURL = %v", url)
	n, states, err := hasher.URLChecksums(
		// context.Context.
		ctx,
		// URL.
		url,
		// Option to set hash algorithms.
		hasher.Algs([]string{"SHA-256"}),
		// Option to set OnDownloadFunc to report progress.
		hasher.OnHash(func(total, prev, current int64, percent float32) {
			log.Printf("%v / %v(%.2f%%) calculated", prev+current, total, percent)

		}),
	)

	if err != nil {
		if err != context.Canceled && err != context.DeadlineExceeded {
			log.Printf("hasher.URLChecksums() error: %v", err)
			return
		} else {
			log.Printf("hasher.URLChecksums() stopped by user, bytes hashed: %v, states: %v\n", n, states)
		}
	} else {
		log.Printf("hasher.URLChecksums() OK")
		fmt.Printf("%x", states["SHA-256"])
	}

	// Call hasher.URLChecksums again to resume previous calculation.
	log.Printf("hasher.URLChecksums() starts again to resume calculation...\nURL = %v", url)
	n, checksums, err := hasher.URLChecksums(
		// context.Context.
		context.Background(),
		// URL.
		url,
		// Option to set states to resume previous calculation.
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
			log.Printf("hasher.URLChecksums() error: %v", err)
			return
		} else {
			log.Printf("hasher.URLChecksums() stopped by user, bytes hashed: %v, states: %v\n", n, states)
		}
	} else {
		log.Printf("hasher.URLChecksums() OK")
		fmt.Printf("%x", checksums["SHA-256"])
	}

	// Output:
	// dd9e772686ed908bcff94b6144322d4e2473a7dcd7c696b7e8b6d12f23c887fd
}

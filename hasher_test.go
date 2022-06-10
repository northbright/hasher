package hasher_test

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/northbright/hasher"
)

func ExampleHasher_Start() {
	hashFuncs := []string{
		"MD5",
		"SHA-1",
	}
	bufferSize := int64(16 * 1024 * 1024)

	h := hasher.New(hashFuncs, bufferSize)

	str := "Hello World!"
	ctx := context.Background()
	// Start computing the hash of the string.
	ch := h.Start(ctx, strings.NewReader(str), 0, 0, nil)

	for event := range ch {
		switch ev := event.(type) {
		case *hasher.ErrorEvent:
			log.Printf("on error: %v", ev.Err())
			return
		case *hasher.StopEvent:
			log.Printf("on stopped:\ncomputed: %v, states: %v", ev.Computed(), ev.States())
		case *hasher.OKEvent:
			log.Printf("on ok:\ncomputed: %v\nchecksums:\n", ev.Computed())
			for name, checksum := range ev.Checksums() {
				log.Printf("%s: %X", name, checksum)
			}
		}
	}

	name := "/Users/xxu/Iso/CentOS-8.1.1911-x86_64-dvd1.iso"
	fi, _ := os.Stat(name)
	size := fi.Size()
	log.Printf("size: %v", size)
	f, _ := os.Open(name)
	defer f.Close()

	ch = h.Start(ctx, f, fi.Size(), time.Millisecond*800, nil)

	for event := range ch {
		switch ev := event.(type) {
		case *hasher.ErrorEvent:
			log.Printf("on error: %v", ev.Err())
			return
		case *hasher.ProgressEvent:
			log.Printf("on progress: %v", ev.Percent())
		case *hasher.StopEvent:
			log.Printf("on stopped:\ncomputed: %v, states: %v", ev.Computed(), ev.States())
		case *hasher.OKEvent:
			log.Printf("on ok:\ncomputed: %v\nchecksums:\n", ev.Computed())
			for name, checksum := range ev.Checksums() {
				log.Printf("%s: %X", name, checksum)
			}
		}
	}

	// Output:
}

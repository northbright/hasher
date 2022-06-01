package hasher_test

import (
	"context"
	"log"
	"strings"

	"github.com/northbright/hasher"
)

func ExampleHasher_Start() {
	hashFuncs := []string{
		"MD5",
		"SHA-1",
	}
	bufferSize := int64(16 * 1024 * 1024)

	h, err := hasher.New(hashFuncs, bufferSize)
	if err != nil {
		log.Printf("new hasher error: %v", err)
		return
	}

	str := "Hello World!"
	ctx := context.Background()
	// Start computing the hash of the string.
	ch := h.Start(ctx, strings.NewReader(str), nil, 0)

	for event := range ch {
		switch ev := event.(type) {
		case *hasher.ErrorEvent:
			log.Printf("on error: %v", ev.Err())
			return
		case *hasher.ComputedEvent:
			log.Printf("on computed: %v", ev.Computed())
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

package hasher

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/northbright/httputil"
	"github.com/northbright/iocopy"
)

// crc32NewIEEE is a wrapper of crc32.NewIEEE.
// Make it possible to return a hash.Hash instead of hash.Hash32.
func crc32NewIEEE() hash.Hash {
	return hash.Hash(crc32.NewIEEE())
}

var (
	hashAlgsToNewFuncs = map[string]func() hash.Hash{
		"MD5":     md5.New,
		"SHA-1":   sha1.New,
		"SHA-256": sha256.New,
		"SHA-512": sha512.New,
		"CRC-32":  crc32NewIEEE,
	}

	// ErrUnSupportedHashAlg indicates that the hash algorithm is not supported.
	ErrUnSupportedHashAlg = errors.New("unsupported hash algorithm")

	// No states specified
	ErrNoStates = errors.New("no states")

	// Not encoding.BinaryMarshaler
	ErrNotBinaryMarshaler = errors.New("not binary marshaler")

	// Not encoding.BinaryUnmarshaler
	ErrNotBinaryUnmarshaler = errors.New("not binary unmarshaler")

	// No checksums computed.
	ErrNoChecksums = errors.New("no checksums computed")

	// Incorrect computed size.
	ErrIncorrectComputedSize = errors.New("incorrect computed size")

	// Range header is not supported by the server.
	ErrRangeNotSupported = errors.New("range header is not supported")

	// Status code is not 200.
	ErrStatusCodeIsNot200 = errors.New("status code is not 200")

	// Status code is not 206.
	ErrStatusCodeIsNot206 = errors.New("status code is not 206")
)

// SupportedHashAlgs returns supported hash algorithms of this package.
func SupportedHashAlgs() []string {
	var algs []string

	for alg := range hashAlgsToNewFuncs {
		algs = append(algs, alg)
	}

	// Sort hash algorithms by names.
	sort.Slice(algs, func(i, j int) bool {
		return algs[i] < algs[j]
	})

	return algs
}

// Hasher is used to compute hash algorithm checksums.
type Hasher struct {
	r      io.Reader
	hashes map[string]hash.Hash
}

// New creates a new Hasher.
// r: io.Reader to read data from.
// hashAlgs: hash algorithms to compute checksums.
func New(r io.Reader, hashAlgs ...string) (*Hasher, error) {
	hashes := make(map[string]hash.Hash)

	if hashAlgs == nil {
		// Use all supported hash algorithms by default.
		hashAlgs = SupportedHashAlgs()
	}

	for _, alg := range hashAlgs {
		f, ok := hashAlgsToNewFuncs[alg]
		if !ok {
			return nil, ErrUnSupportedHashAlg
		}
		// Call f function to new a hash.Hash and insert it to the map.
		hashes[alg] = f()
	}

	return &Hasher{r: r, hashes: hashes}, nil
}

func NewWithStates(r io.Reader, states map[string][]byte) (*Hasher, error) {
	var (
		algs []string
	)

	if states == nil {
		return nil, ErrNoStates
	}

	for alg := range states {
		algs = append(algs, alg)
	}

	h, err := New(r, algs...)
	if err != nil {
		return nil, err
	}

	// Load binary state for each hash.Hash.
	for alg, hash := range h.hashes {
		unmarshaler, ok := hash.(encoding.BinaryUnmarshaler)
		if !ok {
			return nil, ErrNotBinaryUnmarshaler
		}

		if err := unmarshaler.UnmarshalBinary(states[alg]); err != nil {
			return nil, err
		}
	}

	return h, nil
}

func FromStrings(strs []string, hashAlgs ...string) (*Hasher, error) {
	var (
		readers []io.Reader
	)

	for _, str := range strs {
		readers = append(readers, strings.NewReader(str))
	}

	r := io.MultiReader(readers...)

	return New(r, hashAlgs...)
}

func FromString(str string, hashAlgs ...string) (*Hasher, error) {
	return FromStrings([]string{str}, hashAlgs...)
}

func FromUrlWithStates(
	url string,
	computed int64,
	states map[string][]byte,
	hashAlgs ...string) (h *Hasher, total int64, err error) {

	if computed < 0 {
		return nil, 0, ErrIncorrectComputedSize
	}

	// Get remote content length and
	// check if range header is supported by the server.
	total, isRangeSupported, err := httputil.ContentLength(url)
	if err != nil {
		return nil, 0, err
	}

	// Create a HTTP client.
	client := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}

	// Load states if computed > 0.
	if computed > 0 {
		if !isRangeSupported {
			return nil, 0, ErrRangeNotSupported
		}

		// Set range header.
		bytesRange := fmt.Sprintf("bytes=%d-", computed)
		req.Header.Add("range", bytesRange)

		// Do HTTP request.
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}

		// Check if status code is 206.
		if resp.StatusCode != 206 {
			return nil, 0, ErrStatusCodeIsNot206
		}

		// Create a hasher with states.
		h, err := NewWithStates(resp.Body, states)
		if err != nil {
			return nil, 0, err
		}

		return h, total, nil
	} else {
		// computed == 0, read from the start of the response body.

		// Do HTTP request.
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}

		// Check if status code is 200.
		if resp.StatusCode != 200 {
			return nil, 0, ErrStatusCodeIsNot200
		}

		// Create a hasher.
		h, err := New(resp.Body, hashAlgs...)
		if err != nil {
			return nil, 0, err
		}

		return h, total, nil
	}
}

func FromUrl(
	url string,
	hashAlgs ...string) (h *Hasher, total int64, err error) {
	return FromUrlWithStates(url, 0, nil, hashAlgs...)
}

func (h *Hasher) States() (map[string][]byte, error) {
	var states = make(map[string][]byte)

	for alg, hash := range h.hashes {
		marshaler, ok := hash.(encoding.BinaryMarshaler)
		if !ok {
			return nil, ErrNotBinaryMarshaler
		}

		state, err := marshaler.MarshalBinary()
		if err != nil {
			return nil, err
		}

		states[alg] = state
	}

	return states, nil
}

func (h *Hasher) Checksums() map[string][]byte {
	var checksums = make(map[string][]byte)

	for alg, hash := range h.hashes {
		checksums[alg] = hash.Sum(nil)
	}

	return checksums
}

// Start starts a worker goroutine to read data and compute hashes.
// It wraps the basic iocopy.Start fucntion.
// See https://pkg.go.dev/github.com/northbright/iocopy#Start for more information.
// ctx: context.Context.
// bufSize: size of the buffer. It'll create a buffer in the new goroutine according to the buffer size.
// interval: interval to send EventWritten event to the channel.
// You may set it to DefaultInterval.
// tryClosingReaderOnExit: if need to try closing the reader on goroutine exit.
// Caller may set it to true when src is an io.ReadCloser.
// e.g. http.Response.Body, os.File.
//
// It returns a channel to receive IO copy events.
// There're 4 types of events will be send to the channel:
// (1). n bytes have been written successfully.
//
//	It'll send an EventWritten to the channel.
//
// (2). an error occured
//
//	It'll send an EventError to the channel and close the channel.
//
// (3). IO copy stopped(context is canceled or context's deadline exceeded).
//
//	It'll send an EventStop to the channel and close the channel.
//
// (4). IO copy succeeded.
//
//	It'll send an EventOK to the channel and close the channel.
//
// You may use a for-range loop to read events from the channel.
func (h *Hasher) Start(
	ctx context.Context,
	bufSize int64,
	interval time.Duration,
	tryClosingReaderOnExit bool) <-chan iocopy.Event {

	var (
		writers []io.Writer
	)

	for _, w := range h.hashes {
		writers = append(writers, w)
	}

	// Create a multi-writer to compute multiple hash algorithms
	// checksums.
	w := io.MultiWriter(writers...)

	// Return an event channel and start to copy.
	return iocopy.Start(ctx, w, h.r, bufSize, interval, tryClosingReaderOnExit)
}

func (h *Hasher) Compute(
	ctx context.Context,
	tryClosingReaderOnExit bool) (checksums map[string][]byte, written int64, err error) {
	ch := h.Start(
		ctx,
		iocopy.DefaultBufSize,
		iocopy.DefaultInterval,
		tryClosingReaderOnExit)

	for event := range ch {
		switch ev := event.(type) {
		case *iocopy.EventError:
			err := ev.Err()
			return nil, 0, err

		case *iocopy.EventStop:
			err := ev.Err()
			return nil, 0, err

		case *iocopy.EventOK:
			n := ev.Written()
			checksums := h.Checksums()
			return checksums, n, nil
		}
	}

	return nil, 0, ErrNoChecksums
}

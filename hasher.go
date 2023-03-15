package hasher

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"os"
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

// Hasher is used to compute the hash algorithm checksums.
type Hasher struct {
	r               io.Reader
	needCloseReader bool
	hashes          map[string]hash.Hash
}

func newHasher(r io.Reader, needCloseReader bool, hashAlgs ...string) (*Hasher, error) {
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

	return &Hasher{r: r, needCloseReader: false, hashes: hashes}, nil
}

// New creates a new Hasher.
// r: io.Reader to read data from.
// hashAlgs: hash algorithms to compute the checksums.
func New(r io.Reader, hashAlgs ...string) (*Hasher, error) {
	return newHasher(r, false, hashAlgs...)
}

func newHasherWithStates(
	r io.Reader,
	needCloseReader bool,
	states map[string][]byte) (*Hasher, error) {
	var (
		algs []string
	)

	if states == nil {
		return nil, ErrNoStates
	}

	for alg := range states {
		algs = append(algs, alg)
	}

	h, err := newHasher(r, needCloseReader, algs...)
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

// NewWithStates creates a new Hasher with saved states.
// r: io.Reader to read data from. The offset to read at should match the saved states.
// states: a map stores the saved states.
// The key is the hash algorithm and the value is the state in byte slice.
func NewWithStates(r io.Reader, states map[string][]byte) (*Hasher, error) {
	return newHasherWithStates(r, false, states)
}

// Close closes the hasher.
// It's not goroutine-safe and should be called only if computing is done / stopped.
func (h *Hasher) Close() {
	// Close the reader if need.
	if h.needCloseReader {
		if closer, ok := h.r.(io.ReadCloser); ok {
			closer.Close()
		}
	}
}

// FromStrings creates a new Hasher to compute the hashes for the strings.
// strs: string slice to compute hashes.
// hashAlgs: hash algorithms.
func FromStrings(strs []string, hashAlgs ...string) (*Hasher, error) {
	var (
		readers []io.Reader
	)

	for _, str := range strs {
		readers = append(readers, strings.NewReader(str))
	}

	r := io.MultiReader(readers...)

	return newHasher(r, false, hashAlgs...)
}

// FromString creates a new Hasher to compute the hashes for the string.
// str: string to compute hashes.
// hashAlgs: hash algorithms.
func FromString(str string, hashAlgs ...string) (*Hasher, error) {
	return FromStrings([]string{str}, hashAlgs...)
}

// FromUrl creates a new Hasher to compute the hashes for the URL.
// url: URL to compute hashes.
// hashAlgs: hash algorithms.
func FromUrl(
	url string,
	hashAlgs ...string) (h *Hasher, total int64, err error) {

	// Get remote content length and
	// check if range header is supported by the server.
	total, _, err = httputil.ContentLength(url)
	if err != nil {
		return nil, 0, err
	}

	// Create a HTTP client.
	client := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}

	// Do HTTP request.
	// resp.Body(io.ReadCloser) will be closed
	// when Hasher.Close is called.
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	// Check if status code is 200.
	if resp.StatusCode != 200 {
		return nil, 0, ErrStatusCodeIsNot200
	}

	// Create a hasher.
	// Need to close the reader when call Hasher.Close.
	h, err = newHasher(resp.Body, true, hashAlgs...)
	if err != nil {
		return nil, 0, err
	}

	return h, total, nil
}

// FromUrlWithStates creates a new Hasher to contiune to compute the hashes for the URL.
// url: URL to compute the hashes.
// computed: number of computed(hashed) bytes. It should match the saved states.
// states: a map stores the saved states.
// The key is the hash algorithm and the value is the state in byte slice.
func FromUrlWithStates(
	url string,
	computed int64,
	states map[string][]byte) (h *Hasher, total int64, err error) {

	// Check states.
	if states == nil {
		return nil, 0, ErrNoStates
	}

	// Check number of computed bytes.
	if computed <= 0 {
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
	if !isRangeSupported {
		return nil, 0, ErrRangeNotSupported
	}

	// Set range header.
	bytesRange := fmt.Sprintf("bytes=%d-", computed)
	req.Header.Add("range", bytesRange)

	// Do HTTP request.
	// resp.Body(io.ReadCloser) will be closed
	// when Hasher.Close is called.
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	// Check if status code is 206.
	if resp.StatusCode != 206 {
		return nil, 0, ErrStatusCodeIsNot206
	}

	// Create a hasher with states.
	// Need to close the reader when call Hasher.Close.
	h, err = newHasherWithStates(resp.Body, true, states)
	if err != nil {
		return nil, 0, err
	}

	return h, total, nil
}

// FromFile creates a new Hasher to compute the hashes for the file.
// file: file path to compute the hashes.
// hashAlgs: hash algorithms.
func FromFile(
	file string,
	hashAlgs ...string) (h *Hasher, total int64, err error) {

	// Open file.
	// f will be closed when Hasher.Close is called.
	f, err := os.Open(file)
	if err != nil {
		return nil, 0, err
	}

	// Get file info.
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}

	// Get file size.
	total = fi.Size()

	// Create a hasher.
	// Need to close the reader when call Hasher.Close.
	h, err = newHasher(f, true, hashAlgs...)
	if err != nil {
		return nil, 0, err
	}

	return h, total, nil
}

// FromFileWithStates creates a new Hasher to contiune to compute the hashes for the file.
// file: file path to compute the hashes.
// computed: number of computed(hashed) bytes. It should match the saved states.
// states: a map stores the saved states.
// The key is the hash algorithm and the value is the state in byte slice.
func FromFileWithStates(
	file string,
	computed int64,
	states map[string][]byte) (h *Hasher, total int64, err error) {

	// Check states.
	if states == nil {
		return nil, 0, ErrNoStates
	}

	// Check number of computed bytes.
	if computed <= 0 {
		return nil, 0, ErrIncorrectComputedSize
	}

	// Open file.
	// f will be closed when Hasher.Close is called.
	f, err := os.Open(file)
	if err != nil {
		return nil, 0, err
	}

	// Get file info.
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}

	// Get file size.
	total = fi.Size()

	// Set offset.
	_, err = f.Seek(computed, 0)
	if err != nil {
		return nil, 0, err
	}

	// Create a hasher with states.
	// Need to close the reader when call Hasher.Close.
	h, err = newHasherWithStates(f, true, states)
	if err != nil {
		return nil, 0, err
	}

	return h, total, nil
}

// States returns a map stores the latest states of the hashes. The key is the hash algorithm and the value is the state in a byte slice.
// The states are used to continue to compute the hashes later.
// It's not goroutine-safe and should be called only if iocopy.EventStop received.
// Usage:
// 1. Call Hasher.Start with a context and read events from the channel.
// 2. Cancel the context or the deadline expires.
// 3. Receive iocopy.EventStop event from the channel and then call States.
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

// Checksums returns the checksums of the hash algorithms.
// The checksums are stored in a map(key: algorithm, value: checksum in a byte slice).
// It's not goroutine-safe and should be called only if iocopy.EventOK received.
// Usage:
// 1. Call Hasher.Start with a context and read events from the channel.
// 2. Receive iocopy.EventOK event from the channel and then call Checksums.
func (h *Hasher) Checksums() map[string][]byte {
	var checksums = make(map[string][]byte)

	for alg, hash := range h.hashes {
		checksums[alg] = hash.Sum(nil)
	}

	return checksums
}

// ChecksumStrings returns the checksum strings.
func (h *Hasher) ChecksumStrings() map[string]string {
	var checksums = make(map[string]string)

	for alg, hash := range h.hashes {
		checksums[alg] = hex.EncodeToString(hash.Sum(nil))
	}

	return checksums
}

// Match checks if the given checksum string matches any hash alogrithm's checksum.
// When the checksum string matches, it return true and the matched algorithm.
func (h *Hasher) Match(checksum string) (matched bool, matchedHashAlg string) {
	// Create a map which key is checksum hex string and value is hash algorithm.
	var m = make(map[string]string)

	for alg, hash := range h.hashes {
		m[hex.EncodeToString(hash.Sum(nil))] = alg
	}

	// Make sure use lower string to compare.
	checksum = strings.ToLower(checksum)

	if alg, ok := m[checksum]; ok {
		return true, alg
	}

	return false, ""
}

// Start starts a worker goroutine to read data and compute the hashes.
// It wraps the basic iocopy.Start fucntion.
// See https://pkg.go.dev/github.com/northbright/iocopy#Start for more information.
// ctx: context.Context.
// bufSize: size of the buffer. It'll create a buffer in the new goroutine according to the buffer size.
// interval: interval to send EventWritten event to the channel.
// You may set it to DefaultInterval.
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
	interval time.Duration) <-chan iocopy.Event {

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
	return iocopy.Start(ctx, w, h.r, bufSize, interval)
}

// Compute returns the checksums and number of written(hashed) bytes.
// It blocks the caller's goroutine until the computing is done.
func (h *Hasher) Compute(
	ctx context.Context) (checksums map[string][]byte, written int64, err error) {
	ch := h.Start(
		ctx,
		iocopy.DefaultBufSize,
		iocopy.DefaultInterval)

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

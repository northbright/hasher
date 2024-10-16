package hasher

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/northbright/httputil"
	"github.com/northbright/iocopy"
	"github.com/northbright/iocopy/progress"
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

	// Default hash algorithms.
	DefaultAlgs = []string{"MD5", "SHA-1", "SHA-256"}

	// ErrUnSupportedHashAlg indicates that the hash algorithm is not supported.
	ErrUnSupportedHashAlg = errors.New("unsupported hash algorithm")

	// No state found by given algorithm.
	ErrNoStateFound = errors.New("no state found")

	// Not encoding.BinaryMarshaler
	ErrNotBinaryMarshaler = errors.New("not binary marshaler")

	// Not encoding.BinaryUnmarshaler
	ErrNotBinaryUnmarshaler = errors.New("not binary unmarshaler")
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

type calculator struct {
	algs     []string
	hashed   int64
	states   map[string][]byte
	fn       OnHashFunc
	interval time.Duration
}

// Option sets optional parameters to report progress.
type Option func(c *calculator)

// Algs returns an option to set hash algorithms.
// algs: name of hash algorithms.
// Current supported hash algorithms: MD5, SHA-1, SHA-256, SHA-512, CRC-32.
// Call [SupportedHashAlgs] to get supported hash algorithms programmatically.
// If no hash algorithms specified, it uses [DefaultAlgs].
func Algs(algs []string) Option {
	return func(c *calculator) {
		c.algs = algs
	}
}

// States returns an option to set the states to resume previous hash calculation.
// hashed: number of bytes calculated previously.
// states: map stores the states. key: algorithm, value: binary data.
func States(hashed int64, states map[string][]byte) Option {
	return func(c *calculator) {
		c.hashed = hashed
		c.states = states
	}
}

// OnHashFunc is the callback function when bytes are calculated successfully.
// See [progress.OnWrittenFunc].
type OnHashFunc progress.OnWrittenFunc

// OnHash returns an option to set callback to report progress.
func OnHash(fn OnHashFunc) Option {
	return func(c *calculator) {
		c.fn = fn
	}
}

// OnHashInterval returns an option to set the interval of the callback.
func OnHashInterval(d time.Duration) Option {
	return func(c *calculator) {
		c.interval = d
	}
}

// ChecksumsBuffer returns the checksums of given hash algorithms by reading r.
// ctx: [context.Context].
// It returns states of the hashes instead of checksums
// if the context is canceled or the deadline expires.
// Users can call [States] to get an option and pass it to the next call of [ChecksumsBuffer],
// to resume previous calculation.
// r: read the bytes from r and calculate the hash checksums.
// The reader offset should be corresponding to the previous states when states option is set.
// total: total size of r. It's used to report the progress.
// Set it to -1 if its total size is unknown.
// buf: buffer used for the calculation.
// options: [Option] used to resume previous calculation or report progress.
func ChecksumsBuffer(ctx context.Context, r io.Reader, total int64, buf []byte, options ...Option) (written int64, checksums map[string][]byte, err error) {
	// Set options.
	c := &calculator{}
	for _, option := range options {
		option(c)
	}

	if len(c.algs) == 0 {
		c.algs = DefaultAlgs
	}

	hashes := make(map[string]hash.Hash)
	var writers []io.Writer

	// Create hash.Hash by algorithm
	for _, alg := range c.algs {
		// Use upper case letters for algorithm.
		alg = strings.ToUpper(alg)

		// Get new function for the algorithm.
		f, ok := hashAlgsToNewFuncs[alg]
		if !ok {
			return 0, nil, ErrUnSupportedHashAlg
		}
		// Call f function to new a hash.Hash and insert it to the map.
		hashes[alg] = f()

		// Resume previous calculation by loading binary states.
		if c.hashed > 0 && len(c.states) > 0 {
			state, ok := c.states[alg]
			if !ok {
				return 0, nil, ErrNoStateFound
			}

			unmarshaler, ok := hashes[alg].(encoding.BinaryUnmarshaler)
			if !ok {
				return 0, nil, ErrNotBinaryUnmarshaler
			}

			if err = unmarshaler.UnmarshalBinary(state); err != nil {
				return 0, nil, err
			}
		}

		writers = append(writers, hashes[alg])
	}

	w := io.MultiWriter(writers...)

	var writer io.Writer = w

	if c.fn != nil {
		// Create a progress.
		p := progress.New(
			// Total size.
			total,
			// OnWrittenFunc.
			progress.OnWrittenFunc(c.fn),
			// Option to set number of bytes copied previously.
			progress.Prev(c.hashed),
			// Option to set interval.
			progress.Interval(c.interval),
		)

		// Create a multiple writer and dupllicates writes to p.
		writer = io.MultiWriter(w, p)

		// Create a channel.
		// Send an empty struct to it to make progress goroutine exit.
		chExit := make(chan struct{}, 1)
		defer func() {
			chExit <- struct{}{}
		}()

		// Starts a new goroutine to report progress until ctx.Done() and chExit receive an empty struct.
		p.Start(ctx, chExit)
	}

	if len(buf) != 0 {
		written, err = iocopy.CopyBuffer(ctx, writer, r, buf)
	} else {
		written, err = iocopy.Copy(ctx, writer, r)
	}

	if err != nil {
		if err != context.Canceled && err != context.DeadlineExceeded {
			return written, nil, err
		} else {
			// Calculation stopped.
			// Return states instead of checksums.
			states := make(map[string][]byte)
			for alg, h := range hashes {
				marshaler, ok := h.(encoding.BinaryMarshaler)
				if !ok {
					return 0, nil, ErrNotBinaryMarshaler
				}

				state, err := marshaler.MarshalBinary()
				if err != nil {
					return 0, nil, err
				}

				states[alg] = state
			}

			return written, states, err
		}
	} else {
		checksums = make(map[string][]byte)

		for alg, h := range hashes {
			checksums[alg] = h.Sum(nil)
		}

		return written, checksums, nil
	}
}

// Checksums returns the checksums of given hash algorithms by reading r.
// ctx: [context.Context].
// It returns states of the hashes instead of checksums
// if the context is canceled or the deadline expires.
// Users can call [States] to get an option and pass it to the next call of [ChecksumsBuffer],
// to resume previous calculation.
// r: read the bytes from r and calculate the hash checksums.
// total: total size of r. It's used to report the progress.
// Set it to -1 if its total size is unknown.
// options: [Option] used to resume previous calculation or report progress.
func Checksums(ctx context.Context, r io.Reader, total int64, options ...Option) (written int64, checksums map[string][]byte, err error) {
	return ChecksumsBuffer(ctx, r, total, nil, options...)
}

// FileChecksumsBuffer reads the file and returns the checksums of given hash algorithms.
// ctx: [context.Context].
// It returns states of the hashes instead of checksums
// if the context is canceled or the deadline expires.
// Users can call [States] to get an option and pass it to the next call of [ChecksumsBuffer],
// to resume previous calculation.
// filename: file to calculate the hash checksums.
// buf: buffer used for the calculation.
// options: [Option] used to resume previous calculation or report progress.
func FileChecksumsBuffer(ctx context.Context, filename string, buf []byte, options ...Option) (written int64, checksums map[string][]byte, err error) {
	// Set options.
	c := &calculator{}
	for _, option := range options {
		option(c)
	}

	f, err := os.Open(filename)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return 0, nil, err
	}

	total := fi.Size()

	// Resume previous calculation by setting file offset.
	if c.hashed > 0 && len(c.states) > 0 {
		if _, err = f.Seek(c.hashed, io.SeekStart); err != nil {
			return 0, nil, err
		}
	}

	return ChecksumsBuffer(ctx, f, total, buf, options...)
}

// FileChecksums reads the file and returns the checksums of given hash algorithms.
// ctx: [context.Context].
// It returns states of the hashes instead of checksums
// if the context is canceled or the deadline expires.
// Users can call [States] to get an option and pass it to the next call of [ChecksumsBuffer],
// to resume previous calculation.
// filename: file to calculate the hash checksums.
// options: [Option] used to resume previous calculation or report progress.
func FileChecksums(ctx context.Context, filename string, options ...Option) (written int64, checksums map[string][]byte, err error) {
	return FileChecksumsBuffer(ctx, filename, nil, options...)
}

// URLChecksumsBuffer reads the remote file and returns the checksums of given hash algorithms.
// ctx: [context.Context].
// It returns states of the hashes instead of checksums
// if the context is canceled or the deadline expires.
// Users can call [States] to get an option and pass it to the next call of [ChecksumsBuffer],
// to resume previous calculation.
// url: URL of remote file to calculate the hash checksums.
// buf: buffer used for the calculation.
// options: [Option] used to resume previous calculation or report progress.
func URLChecksumsBuffer(ctx context.Context, url string, buf []byte, options ...Option) (written int64, checksums map[string][]byte, err error) {
	// Set options.
	c := &calculator{}
	for _, option := range options {
		option(c)
	}

	resp, total, rangeIsSupported, err := httputil.GetResp(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body

	// Get the HTTP response by range("bytes=start-" syntax) to resume previous calculation.
	if c.hashed > 0 && len(c.states) > 0 {
		if rangeIsSupported {
			resp2, _, err := httputil.GetRespOfRangeStart(
				// URL.
				url,
				// Start.
				c.hashed,
			)
			if err != nil {
				return 0, nil, err
			}
			defer resp2.Body.Close()
			reader = resp2.Body
		}
	}

	return ChecksumsBuffer(ctx, reader, total, buf, options...)
}

// URLChecksums reads the remote file and returns the checksums of given hash algorithms.
// ctx: [context.Context].
// It returns states of the hashes instead of checksums
// if the context is canceled or the deadline expires.
// Users can call [States] to get an option and pass it to the next call of [ChecksumsBuffer],
// to resume previous calculation.
// url: URL of remote file to calculate the hash checksums.
// options: [Option] used to resume previous calculation or report progress.
func URLChecksums(ctx context.Context, url string, options ...Option) (written int64, checksums map[string][]byte, err error) {
	return URLChecksumsBuffer(ctx, url, nil, options...)
}

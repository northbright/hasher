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
	"io"
	"sort"
	"strings"
	"time"

	"github.com/northbright/iocopy"
)

var (
	hashAlgsToNewFuncs = map[string]func() hash.Hash{
		"MD5":     md5.New,
		"SHA-1":   sha1.New,
		"SHA-256": sha256.New,
		"SHA-512": sha512.New,
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
	hashes map[string]hash.Hash
}

// New creates a new Hasher.
// hashAlgs: hash algorithms to compute checksums.
func New(hashAlgs ...string) (*Hasher, error) {
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

	return &Hasher{hashes: hashes}, nil
}

func NewWithStates(states map[string][]byte) (*Hasher, error) {
	var (
		algs []string
	)

	if states == nil {
		return nil, ErrNoStates
	}

	for alg := range states {
		algs = append(algs, alg)
	}

	h, err := New(algs...)
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

func (h *Hasher) Compute(
	ctx context.Context,
	bufSize int64,
	interval time.Duration,
	readers ...io.Reader) <-chan iocopy.Event {

	var (
		writers []io.Writer
	)

	r := io.MultiReader(readers...)

	for _, w := range h.hashes {
		writers = append(writers, w)
	}

	// Create a multi-writer to compute multiple hash algorithms
	// checksums.
	w := io.MultiWriter(writers...)

	// Return an event channel and start to copy.
	return iocopy.Start(ctx, w, r, bufSize, interval)
}

func (h *Hasher) ComputeStrings(strs ...string) (checksums map[string][]byte, written int64, err error) {
	var (
		readers []io.Reader
	)

	for _, str := range strs {
		readers = append(readers, strings.NewReader(str))
	}

	ch := h.Compute(
		context.Background(),
		iocopy.DefaultBufSize,
		iocopy.DefaultInterval,
		readers...)

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

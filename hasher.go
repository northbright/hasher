package hasher

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"sort"
	"strings"

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

	// Default hash algorithms.
	DefaultAlgs = []string{"MD5", "SHA-1", "SHA-256"}

	// ErrUnSupportedHashAlg indicates that the hash algorithm is not supported.
	ErrUnSupportedHashAlg = errors.New("unsupported hash algorithm")
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

// newHashesByAlgs creates a map which its key is algorithm and value is [hash.Hash].
func newHashesByAlgs(algs []string) (map[string]hash.Hash, error) {
	hashes := make(map[string]hash.Hash)

	if len(algs) == 0 {
		algs = DefaultAlgs
	}

	// Create hash.Hash by algorithm
	for _, alg := range algs {
		// Use upper case letters for algorithm.
		alg = strings.ToUpper(alg)

		// Get new function for the algorithm.
		f, ok := hashAlgsToNewFuncs[alg]
		if !ok {
			return nil, ErrUnSupportedHashAlg
		}
		// Call f function to new a hash.Hash and insert it to the map.
		hashes[alg] = f()
	}

	return hashes, nil
}

// ComputeChecksumsBufferWithProgress returns the checksums of given hash algorithms by reading r.
// It accepts [context.Context] to make computing cancalable.
// It also accepts callback function on bytes written to report progress.
func ComputeChecksumsBufferWithProgress(
	ctx context.Context,
	algs []string,
	r io.Reader,
	buf []byte,
	total int64,
	fn iocopy.OnWrittenFunc) (n int64, checksums map[string][]byte, err error) {
	hashes, err := newHashesByAlgs(algs)
	if err != nil {
		return 0, nil, err
	}

	var writers []io.Writer
	for _, h := range hashes {
		writers = append(writers, h)
	}

	w := io.MultiWriter(writers...)

	n, err = iocopy.CopyBufferWithProgress(ctx, w, r, buf, total, 0, fn)
	if err != nil {
		return n, nil, err
	}

	checksums = make(map[string][]byte)
	for alg, h := range hashes {
		checksums[alg] = h.Sum(nil)
	}

	return n, checksums, nil
}

// ComputeChecksums returns the checksums of given hash algorithms by reading r.
// It accepts [context.Context] to make computing cancalable.
func ComputeChecksums(
	ctx context.Context,
	algs []string,
	r io.Reader) (n int64, checksums map[string][]byte, err error) {
	return ComputeChecksumsBufferWithProgress(ctx, algs, r, nil, 0, nil)
}

// ComputeChecksumsBuffer is buffered version of [ComputeChecksums].
func ComputeChecksumsBuffer(
	ctx context.Context,
	algs []string,
	r io.Reader,
	buf []byte) (n int64, checksums map[string][]byte, err error) {
	return ComputeChecksumsBufferWithProgress(ctx, algs, r, buf, 0, nil)
}

// ComputeChecksumsWithProgress is non-buffered version of [ComputeChecksumsBufferWithProgress].
func ComputeChecksumsWithProgress(
	ctx context.Context,
	algs []string,
	r io.Reader,
	total int64,
	fn iocopy.OnWrittenFunc) (n int64, checksums map[string][]byte, err error) {
	return ComputeChecksumsBufferWithProgress(ctx, algs, r, nil, total, fn)
}

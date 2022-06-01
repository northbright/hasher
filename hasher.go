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
	"time"
)

const (
	DefBufSize = int64(32 * 1024)
	MaxBufSize = int64(4 * 1024 * 1024 * 1024)
)

var (
	ErrNoHashFunc                  = errors.New("no hash function specified")
	ErrUnmatchedHashFuncsAndStates = errors.New("unmatched hash functions and states")
	ErrNotBinaryUnmarshaler        = errors.New("encoding.BinaryUnmarshaler not implemented")
	ErrNotBinaryMarshaler          = errors.New("encoding.BinaryMarshaler not implemented")
	ErrUnSupportedHashFunc         = errors.New("unsupported hash function")
	ErrUnmatchedStringLenAndOffset = errors.New("unmatched string length and offset")
	SupportedHashFuncs             = []string{
		"MD5",
		"CRC-32",
		"SHA-1",
		"SHA-256",
		"SHA-512",
	}
)

func GetSupportedHashFuncs() []string {
	return SupportedHashFuncs
}

func GetHashByName(name string) (hash.Hash, error) {

	switch name {
	case "MD5":
		return md5.New(), nil
	case "CRC-32":
		return crc32.NewIEEE(), nil
	case "SHA-1":
		return sha1.New(), nil
	case "SHA-256":
		return sha256.New(), nil
	case "SHA-512":
		return sha512.New(), nil
	default:
		return nil, ErrUnSupportedHashFunc
	}
}

func updateBufferSize(bufferSize int64) int64 {
	switch {
	case bufferSize <= 0:
		return DefBufSize
	case bufferSize > MaxBufSize:
		return MaxBufSize
	default:
		return bufferSize
	}
}

type Hasher struct {
	hashes     map[string]hash.Hash
	w          io.Writer
	bufferSize int64
}

func New(hashFuncs []string, bufferSize int64) (*Hasher, error) {
	var (
		hashes  = make(map[string]hash.Hash)
		writers []io.Writer
	)

	if hashFuncs == nil || len(hashFuncs) == 0 {
		return nil, ErrNoHashFunc
	}

	// Get hash.Hash from hash func name.
	for _, name := range hashFuncs {
		hash, err := GetHashByName(name)
		if err != nil {
			return nil, err
		}

		hashes[name] = hash
		writers = append(writers, hash)
	}

	w := io.MultiWriter(writers...)

	hasher := &Hasher{
		hashes:     hashes,
		w:          w,
		bufferSize: updateBufferSize(bufferSize),
	}

	return hasher, nil
}

func (h *Hasher) loadStates(states map[string][]byte) error {
	if states == nil {
		return nil
	}

	if len(h.hashes) != len(states) {
		return ErrUnmatchedHashFuncsAndStates
	}

	for name := range h.hashes {
		if _, ok := states[name]; !ok {
			return ErrUnmatchedHashFuncsAndStates
		}
	}

	// Load states
	for name, hash := range h.hashes {
		// Convert hash to encoding.BinaryUnmarshaler
		u, ok := hash.(encoding.BinaryUnmarshaler)
		if !ok {
			return ErrNotBinaryUnmarshaler
		}

		if err := u.UnmarshalBinary(states[name]); err != nil {
			return err
		}
	}

	return nil
}

func (h *Hasher) states() (map[string][]byte, error) {
	states := make(map[string][]byte)

	for name, hash := range h.hashes {
		// Convert hash to encoding.BinaryMarshaler
		u, ok := hash.(encoding.BinaryMarshaler)
		if !ok {
			return nil, ErrNotBinaryMarshaler
		}

		state, err := u.MarshalBinary()
		if err != nil {
			return nil, err
		}

		states[name] = state
	}

	return states, nil
}

func (h *Hasher) Start(
	ctx context.Context,
	r io.Reader,
	states map[string][]byte,
	reportComputedInterval time.Duration,
) <-chan Event {
	ch := make(chan Event)

	go func(ch chan Event) {
		defer func() {
			close(ch)
		}()

		var (
			ticker *time.Ticker = nil
		)

		if states != nil {
			if err := h.loadStates(states); err != nil {
				ch <- newErrorEvent(err)
				return
			}
		}

		computed := int64(0)

		buf := make([]byte, h.bufferSize)

		if reportComputedInterval > 0 {
			ticker = time.NewTicker(reportComputedInterval)
		}

		for {
			if ticker != nil {
				select {
				case <-ticker.C:
					ch <- newComputedEvent(computed)
				default:
				}
			}

			select {
			case <-ctx.Done():
				states, err := h.states()
				if err != nil {
					ch <- newErrorEvent(err)
					return
				}
				ch <- newStopEvent(computed, states)
				return
			default:
				n, err := io.CopyBuffer(h.w, r, buf)
				if err != nil {
					ch <- newErrorEvent(err)
					return
				}

				if n == 0 {
					checksums := make(map[string][]byte)

					for name, hash := range h.hashes {
						checksums[name] = hash.Sum(nil)
					}

					ch <- newOKEvent(computed, checksums)
					return
				}

				computed += n

			}

		}
	}(ch)

	return ch
}

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
	"log"
	"time"
)

const (
	// DefBufSize is the default buffer size used to compute hashes.
	DefBufSize = int64(32 * 1024)
	// MaxBufSize is the max buffer size.
	MaxBufSize = int64(4 * 1024 * 1024 * 1024)
)

var (
	// Debug turns on / off debug mode.
	// It'll output debug messages in debug mode.
	Debug = false

	// ErrNoHashFunc is returned by getHashesAndWriter when there's no hash function specified.
	ErrNoHashFunc = errors.New("no hash function specified")

	// ErrUnmatchedHashFuncsAndStates is returned by Hasher.Start when hash functions and states are unmatched.
	ErrUnmatchedHashFuncsAndStates = errors.New("unmatched hash functions and states")

	// ErrNotBinaryUnmarshaler is returned by Hasher.Start when encoding.BinaryUnmarshaler is not implemented.
	ErrNotBinaryUnmarshaler = errors.New("encoding.BinaryUnmarshaler not implemented")

	// ErrNotBinaryMarshaler is returned by Hasher.Start when encoding.BinaryMarshaler is not implemented.
	ErrNotBinaryMarshaler = errors.New("encoding.BinaryMarshaler not implemented")

	// ErrUnSupportedHashFunc is returned by GetHashByName to indicate that the hash function is not supported.
	ErrUnSupportedHashFunc = errors.New("unsupported hash function")

	// DefReportProgressInterval is used in Hasher.Start as the default interval to report the progress of computing hashes.
	DefReportProgressInterval = time.Millisecond * 500
)

// AvailableHashFuncs returns the available hash functions.
func AvailableHashFuncs() []string {
	return []string{
		"MD5",
		"CRC-32",
		"SHA-1",
		"SHA-256",
		"SHA-512",
	}
}

// GetHashByName returns the hash.Hash by given hash function name.
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

// updateBufferSize checks and returns a valid buffer size.
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

// A Hasher is used to compute hashes.
type Hasher struct {
	hashFuncs  []string
	bufferSize int64
}

// getHashesAndWriter returns a map(key: hash function name, value: hash.Hash) and the a multiple writer.
func getHashesAndWriter(hashFuncs []string) (map[string]hash.Hash, io.Writer, error) {
	var (
		hashes  = make(map[string]hash.Hash)
		writers []io.Writer
	)

	if len(hashFuncs) == 0 {
		return nil, nil, ErrNoHashFunc
	}

	// Get hash.Hash from hash func name.
	for _, name := range hashFuncs {
		hash, err := GetHashByName(name)
		if err != nil {
			return nil, nil, err
		}

		hashes[name] = hash
		writers = append(writers, hash)
	}

	w := io.MultiWriter(writers...)

	return hashes, w, nil
}

// New creates a Hasher by given hash function names and buffer size.
func New(hashFuncs []string, bufferSize int64) *Hasher {
	return &Hasher{
		hashFuncs:  hashFuncs,
		bufferSize: updateBufferSize(bufferSize),
	}
}

// loadStates loads the saved states.
// hashes is a map which key is hash function name and value is hash.Hash.
// states is a map which key is hash function name and value is the state in byte slice.
func loadStates(hashes map[string]hash.Hash, states map[string][]byte) error {
	if states == nil {
		return nil
	}

	if len(hashes) != len(states) {
		return ErrUnmatchedHashFuncsAndStates
	}

	for name := range hashes {
		if _, ok := states[name]; !ok {
			return ErrUnmatchedHashFuncsAndStates
		}
	}

	// Load states
	for name, hash := range hashes {
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

// outputStates outputs the states.
// hashes: a map which key is hash function name and value is hash.Hash.
// return: a map which key is hash function name and value is the state in byte slice.
func outputStates(hashes map[string]hash.Hash) (map[string][]byte, error) {
	states := make(map[string][]byte)

	for name, hash := range hashes {
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

// ComputePercent computes the progress percent.
func ComputePercent(total, current int64) float32 {
	if total > 0 {
		return float32(float64(current) / (float64(total) / float64(100)))
	}
	return 0
}

// Start returns a Event channel to receive events and starts a goroutine to compute hashes.
// ctx: context.Context.
// r: io.Reader to read the data from.
// total: total size to read and compute hashes.
// reportProgressInterval: interval to report the progress of computing hashes.
// It will be set to DefReportProgressInterval if it's 0.
// states: a map contains the states(key: hash function name, value: state in byte slice)
func (h *Hasher) Start(
	ctx context.Context,
	r io.Reader,
	total int64,
	reportProgressInterval time.Duration,
	states map[string][]byte,
) <-chan Event {
	ch := make(chan Event)

	go func(ch chan Event) {
		var (
			ticker              *time.Ticker = nil
			percent, oldPercent float32
		)

		defer func() {
			close(ch)
			if ticker != nil {
				ticker.Stop()
			}
		}()

		// Get hashes and multiple writer.
		hashes, w, err := getHashesAndWriter(h.hashFuncs)
		if err != nil {
			ch <- newErrorEvent(err)
			return
		}

		if states != nil {
			if err := loadStates(hashes, states); err != nil {
				ch <- newErrorEvent(err)
				return
			}
		}

		computed := int64(0)
		buf := make([]byte, h.bufferSize)

		if reportProgressInterval <= 0 {
			reportProgressInterval = DefReportProgressInterval
		}

		ticker = time.NewTicker(reportProgressInterval)
		if total <= 0 {
			ticker.Stop()
		}

		for {
			select {
			case t := <-ticker.C:
				if Debug == true {
					log.Printf("ticker: t: %v", t)
				}

				if total > 0 {
					percent = ComputePercent(total, computed)
					if Debug == true {
						log.Printf("percent: %v", percent)
					}

					if percent != oldPercent {
						oldPercent = percent
						ch <- newProgressEvent(total, computed, percent)
					}
				}

			case <-ctx.Done():
				states, err := outputStates(hashes)
				if err != nil {
					ch <- newErrorEvent(err)
					return
				}
				ch <- newStopEvent(computed, states)
				return
			default:
				n, err := r.Read(buf)
				if err != nil && err != io.EOF {
					ch <- newErrorEvent(err)
					return
				}

				if n == 0 {
					checksums := make(map[string][]byte)

					for name, hash := range hashes {
						checksums[name] = hash.Sum(nil)
					}

					ch <- newOKEvent(computed, checksums)
					return
				} else {
					if n, err = w.Write(buf[:n]); err != nil {
						ch <- newErrorEvent(err)
						return
					}
				}

				computed += int64(n)
			}
		}
	}(ch)

	return ch
}

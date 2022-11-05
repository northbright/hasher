package hasher

import "time"

// Event represents the event when computing hashes.
type Event interface {
	When() time.Time
}

type event struct {
	t time.Time
}

func newEvent() *event {
	return &event{t: time.Now()}
}

func (e *event) When() time.Time {
	return e.t
}

// ErrorEvent occurs when a error occurs when computing hashes.
type ErrorEvent struct {
	*event
	e error
}

func newErrorEvent(err error) *ErrorEvent {
	return &ErrorEvent{event: newEvent(), e: err}
}

// Err returns the error contained in the event.
func (ev *ErrorEvent) Err() error {
	return ev.e
}

type computedEvent struct {
	*event
	computed int64
}

func newComputedEvent(computed int64) *computedEvent {
	return &computedEvent{event: newEvent(), computed: computed}
}

func (ev *computedEvent) Computed() int64 {
	return ev.computed
}

// ProgressEvent occurs when the progress of computing hashes updates.
type ProgressEvent struct {
	*event
	total   int64
	current int64
	percent float32
}

func newProgressEvent(total int64, current int64, percent float32) *ProgressEvent {
	return &ProgressEvent{event: newEvent(), total: total, current: current, percent: percent}
}

// Total returns totoal progress.
func (ev *ProgressEvent) Total() int64 {
	return ev.total
}

// Current return current progress.
func (ev *ProgressEvent) Current() int64 {
	return ev.current
}

// Percent returns the percent of current progress.
func (ev *ProgressEvent) Percent() float32 {
	return ev.percent
}

// StopEvent occurs when computing hashes is stopped.
type StopEvent struct {
	*computedEvent
	states map[string][]byte
}

func newStopEvent(computed int64, states map[string][]byte) *StopEvent {
	return &StopEvent{
		computedEvent: newComputedEvent(computed),
		states:        states,
	}
}

// States returns the states which can be used to compute hashes next time.
// The states are stored in a map which key is the hash function name and value is the state in byte slice.
func (ev *StopEvent) States() map[string][]byte {
	return ev.states
}

// OKEvent occurs when computing hashes is done.
type OKEvent struct {
	*computedEvent
	checksums map[string][]byte
}

func newOKEvent(computed int64, checksums map[string][]byte) *OKEvent {
	return &OKEvent{
		computedEvent: newComputedEvent(computed),
		checksums:     checksums,
	}
}

// Checksums returns the checksums.
// The checksums are stored in a map which key is the hash function name and value is the checksum in byte slice.
func (ev *OKEvent) Checksums() map[string][]byte {
	return ev.checksums
}

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

// EventError occurs when a error occurs when computing hashes.
type EventError struct {
	*event
	e error
}

func newEventError(err error) *EventError {
	return &EventError{event: newEvent(), e: err}
}

// Err returns the error contained in the event.
func (ev *EventError) Err() error {
	return ev.e
}

type eventComputed struct {
	*event
	computed int64
}

func newEventComputed(computed int64) *eventComputed {
	return &eventComputed{event: newEvent(), computed: computed}
}

func (ev *eventComputed) Computed() int64 {
	return ev.computed
}

// EventProgress occurs when the progress of computing hashes updates.
type EventProgress struct {
	*event
	total   int64
	current int64
	percent float32
}

func newEventProgress(total int64, current int64, percent float32) *EventProgress {
	return &EventProgress{event: newEvent(), total: total, current: current, percent: percent}
}

// Total returns totoal progress.
func (ev *EventProgress) Total() int64 {
	return ev.total
}

// Current return current progress.
func (ev *EventProgress) Current() int64 {
	return ev.current
}

// Percent returns the percent of current progress.
func (ev *EventProgress) Percent() float32 {
	return ev.percent
}

// EventStop occurs when computing hashes is stopped.
type EventStop struct {
	*eventComputed
	states map[string][]byte
}

func newEventStop(computed int64, states map[string][]byte) *EventStop {
	return &EventStop{
		eventComputed: newEventComputed(computed),
		states:        states,
	}
}

// States returns the states which can be used to compute hashes next time.
// The states are stored in a map which key is the hash function name and value is the state in byte slice.
func (ev *EventStop) States() map[string][]byte {
	return ev.states
}

// EventOK occurs when computing hashes is done.
type EventOK struct {
	*eventComputed
	checksums map[string][]byte
}

func newEventOK(computed int64, checksums map[string][]byte) *EventOK {
	return &EventOK{
		eventComputed: newEventComputed(computed),
		checksums:     checksums,
	}
}

// Checksums returns the checksums.
// The checksums are stored in a map which key is the hash function name and value is the checksum in byte slice.
func (ev *EventOK) Checksums() map[string][]byte {
	return ev.checksums
}

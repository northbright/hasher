package hasher

import "time"

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

type ErrorEvent struct {
	*event
	e error
}

func newErrorEvent(err error) *ErrorEvent {
	return &ErrorEvent{event: newEvent(), e: err}
}

func (ev *ErrorEvent) Err() error {
	return ev.e
}

type ComputedEvent struct {
	*event
	computed int64
}

func newComputedEvent(computed int64) *ComputedEvent {
	return &ComputedEvent{event: newEvent(), computed: computed}
}

func (ev *ComputedEvent) Computed() int64 {
	return ev.computed
}

type StopEvent struct {
	*ComputedEvent
	states map[string][]byte
}

func newStopEvent(computed int64, states map[string][]byte) *StopEvent {
	return &StopEvent{
		ComputedEvent: newComputedEvent(computed),
		states:        states,
	}
}

func (ev *StopEvent) States() map[string][]byte {
	return ev.states
}

type OKEvent struct {
	*ComputedEvent
	checksums map[string][]byte
}

func newOKEvent(computed int64, checksums map[string][]byte) *OKEvent {
	return &OKEvent{
		ComputedEvent: newComputedEvent(computed),
		checksums:     checksums,
	}
}

func (ev *OKEvent) Checksums() map[string][]byte {
	return ev.checksums
}

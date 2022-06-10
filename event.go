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

type ProgressEvent struct {
	*event
	total   int64
	current int64
	percent float32
}

func newProgressEvent(total int64, current int64, percent float32) *ProgressEvent {
	return &ProgressEvent{event: newEvent(), total: total, current: current, percent: percent}
}

func (ev *ProgressEvent) Total() int64 {
	return ev.total
}

func (ev *ProgressEvent) Current() int64 {
	return ev.current
}

func (ev *ProgressEvent) Percent() float32 {
	return ev.percent
}

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

func (ev *StopEvent) States() map[string][]byte {
	return ev.states
}

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

func (ev *OKEvent) Checksums() map[string][]byte {
	return ev.checksums
}

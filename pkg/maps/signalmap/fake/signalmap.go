// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"os"
	"time"

	"github.com/cilium/ebpf/perf"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/maps/signalmap"
)

type fakeSignalMap struct {
	messages [][]byte
	interval time.Duration
}

func NewFakeSignalMap(messages [][]byte, interval time.Duration) *fakeSignalMap {
	return &fakeSignalMap{
		messages: messages,
		interval: interval,
	}
}

type fakePerfReader struct {
	index    int
	messages [][]byte
	interval time.Duration
	pause    chan bool
	closed   chan struct{}
}

func (r *fakePerfReader) Read() (perf.Record, error) {
	timer, timerDone := inctimer.New()
	defer timerDone()

	paused := false

	for {
		select {
		case <-r.closed:
			return perf.Record{}, os.ErrClosed
		case paused = <-r.pause:
			if paused {
				continue
			}
		// Block for the given interval between messages
		case <-timer.After(r.interval):
		}
		if r.index == len(r.messages) {
			r.index = 0
		}
		if r.index < len(r.messages) {
			return perf.Record{RawSample: r.messages[r.index]}, nil
		} else {
			return perf.Record{LostSamples: 1}, nil
		}
	}
}

func (r *fakePerfReader) Pause() error {
	r.pause <- true
	return nil
}

func (r *fakePerfReader) Resume() error {
	r.pause <- false
	return nil
}

func (r *fakePerfReader) Close() error {
	close(r.closed)
	return nil
}

func (f fakeSignalMap) NewReader() (signalmap.PerfReader, error) {
	return &fakePerfReader{
		messages: f.messages,
		interval: f.interval,
		pause:    make(chan bool, 100),
		closed:   make(chan struct{}),
	}, nil
}

func (sm *fakeSignalMap) MapName() string {
	return "fakesignalmap"
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"os"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/time"
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

type fakeRingBufReader struct {
	index    int
	messages [][]byte
	interval time.Duration
	closed   chan struct{}
}

func (r *fakeRingBufReader) Read() (ringbuf.Record, error) {
	for {
		select {
		case <-r.closed:
			return ringbuf.Record{}, os.ErrClosed
		// Block for the given interval between messages
		case <-time.After(r.interval):
		}
		if r.index == len(r.messages) {
			r.index = 0
		}
		if r.index < len(r.messages) {
			msg := r.messages[r.index]
			r.index++
			return ringbuf.Record{RawSample: msg}, nil
		}
		// No messages, just return empty record (will loop again)
	}
}

func (r *fakeRingBufReader) Close() error {
	close(r.closed)
	return nil
}

func (f fakeSignalMap) NewReader() (signalmap.RingBufReader, error) {
	return &fakeRingBufReader{
		messages: f.messages,
		interval: f.interval,
		closed:   make(chan struct{}),
	}, nil
}

func (sm *fakeSignalMap) MapName() string {
	return "fakesignalmap"
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package peer

import (
	"errors"
	"fmt"
	"io"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/lock"
)

type buffer struct {
	max    int
	buf    []*peerpb.ChangeNotification
	mu     lock.Mutex
	notify chan struct{}
	stop   chan struct{}
}

// newBuffer creates a buffer of ChangeNotification that is safe for concurrent
// use. The buffer is created with an initial size of 0 and is allowed to grow
// until max is reached.
func newBuffer(max int) *buffer {
	return &buffer{
		max:    max,
		notify: nil,
		stop:   make(chan struct{}),
	}
}

// Len returns the number of elements in the buffer.
func (b *buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}

// Cap returns the capacity of the buffer.
func (b *buffer) Cap() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return cap(b.buf)
}

// Push appends cn to the end of the buffer. An error is returned if its
// maximum capacity is reached or if the buffer is closed.
func (b *buffer) Push(cn *peerpb.ChangeNotification) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.stop:
		return errors.New("buffer closed")
	default:
		if len(b.buf) == b.max {
			return fmt.Errorf("max buffer size=%d reached", b.max)
		}
	}
	b.buf = append(b.buf, cn)
	if b.notify != nil {
		close(b.notify)
		b.notify = nil
	}
	return nil
}

// Pop removes and returns the first element in the buffer. If the buffer is
// empty, Pop blocks until an element is added or Close is called in which case
// io.EOF is returned.
func (b *buffer) Pop() (*peerpb.ChangeNotification, error) {
	b.mu.Lock()
	if len(b.buf) == 0 {
		if b.notify == nil {
			b.notify = make(chan struct{})
		}
		notify := b.notify
		b.mu.Unlock()
		select {
		case <-notify:
			b.mu.Lock()
		case <-b.stop:
			return nil, io.EOF
		}
	}
	// b.buffer may have been closed while waiting for b.mu.Lock
	select {
	case <-b.stop:
		b.mu.Unlock()
		return nil, io.EOF
	default:
	}
	cn := b.buf[0]
	b.buf[0] = nil
	b.buf = b.buf[1:]
	b.mu.Unlock()
	return cn, nil
}

// Close closes the buffer and frees the underlying memory.
func (b *buffer) Close() {
	close(b.stop)
	b.mu.Lock()
	b.buf = nil
	b.mu.Unlock()
}

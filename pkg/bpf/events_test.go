// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/container"
)

func TestEventsSubscribe(t *testing.T) {
	assert := assert.New(t)
	logger := hivetest.Logger(t)
	eb := &eventsBuffer{
		logger:   logger,
		buffer:   container.NewRingBuffer(0),
		eventTTL: time.Second,
	}
	handle, err := eb.dumpAndSubscribe(nil, true)
	assert.NoError(err)

	// should not block, buffer not full.
	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(123)}})
	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(124)}})
	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(125)}})
	assert.Equal("key=123", (<-handle.C()).Key.String())
	assert.Equal("key=124", (<-handle.C()).Key.String())

	for i := range eventSubChanBufferSize {
		assert.False(handle.isClosed(), "should not close until buffer is full")
		assert.Len(eb.subscriptions, 1)
		assert.Len(eb.subscriptions[0].c, i+1)
		eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(i)}})
	}
	time.Sleep(time.Millisecond * 20)
	assert.True(handle.isClosed(), "after filling buffer, should be closed")
	assert.Empty(eb.subscriptions)

	handle, err = eb.dumpAndSubscribe(nil, true)
	assert.NoError(err)
	assert.False(handle.isClosed())
	handle.Close()
	handle.Close()
	assert.True(handle.isClosed(), "after calling close, should be closed")
	assert.Equal(0, eb.buffer.Size())
}

type IntTestKey uint32

func (k IntTestKey) String() string { return fmt.Sprintf("key=%d", k) }
func (k IntTestKey) New() MapKey    { return new(IntTestKey) }

func TestEventsGC(t *testing.T) {
	// Rather than setting a timeout, this testcase will avoid the time
	// dependencies by using two blocking channels to *ensure* the garbage
	// collection occurs in the critical section.
	logger := hivetest.Logger(t)
	m := Map{
		Logger: logger,
	}
	m.initEventsBuffer(32, 0)
	eb := m.events
	dumpStarted := make(chan struct{})
	doneChan := make(chan struct{})

	// Add a bunch of keys. Garbage collection should clean these up.
	keys := []int{}
	for i := range 32 {
		eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(i)}})
	}

	// Garbage collect the ringbuffer, but wait until the main test
	// goroutine begins iterating the objects below before executing the
	// garbage collection. This should make the failure highly reliable.
	go func(dumpStarted, doneChan chan struct{}) {
		<-dumpStarted
		_ = eb.garbageCollect(context.Background())
		close(doneChan)
	}(dumpStarted, doneChan)

	lastDump := false
loop:
	// Tight loop to touch the same internal data structures as the GC
	// goroutine above to try to trigger a data race.
	for {
		if dumpStarted != nil {
			close(dumpStarted)
			dumpStarted = nil
		}
		keys = []int{}
		eb.dumpAndSubscribe(func(e *Event) {
			k := e.Key.(IntTestKey)
			keys = append(keys, int(k))
		}, false)
		if lastDump {
			break
		}
		select {
		case <-doneChan:
			// Do one last full dumpAndSubscribe to ensure the
			// complete final (garbage-collected) map is dumped,
			// so the contents comparison can pass below.
			lastDump = true
			continue loop
		default:
		}
	}

	// Ensure that garbage collection completed its cleanup successfully.
	assert.Empty(t, keys)
	assert.Equal(t, []int{}, keys)
}

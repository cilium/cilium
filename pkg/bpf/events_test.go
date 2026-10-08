// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/stretchr/testify/assert"
)

func TestEventsSubscribe(t *testing.T) {
	eb := newEventsBuffer(hivetest.Logger(t), "test", 32, 0)

	keys := []int{}
	for i := range 32 {
		eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(i)}})
	}

	eb.dumpAndSubscribe(t.Context(), func(e Event) {
		k := e.Key.(IntTestKey)
		keys = append(keys, int(k))
	}, true)

	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(1000)}})
	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(1001)}})

	assert.Len(t, keys, 34)
	assert.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 1000, 1001}, keys)
}

type IntTestKey uint32

func (k IntTestKey) String() string { return fmt.Sprintf("key=%d", k) }
func (k IntTestKey) New() MapKey    { return new(IntTestKey) }

func TestEventsGC(t *testing.T) {
	// Rather than setting a timeout, this testcase will avoid the time
	// dependencies by using two blocking channels to *ensure* the garbage
	// collection occurs in the critical section.
	eb := newEventsBuffer(hivetest.Logger(t), "test", 32, 0)
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
		eb.dumpAndSubscribe(t.Context(), func(e Event) {
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

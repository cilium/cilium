// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyedMutexDifferentKeys(t *testing.T) {
	const (
		keyA = "instance-a"
		keyB = "instance-b"
	)

	var m KeyedMutex[string]

	// Simulate a locked operation on "instance-a"
	unlockFirst := m.Lock(keyA)
	done := make(chan struct{})

	// Simulate a concurrent locked operation on "instance-b"
	go func() {
		unlock := m.Lock(keyB)
		unlock()
		close(done)
	}()

	// "instance-b" must make progress while "instance-a" remains locked.
	<-done

	// unlock "instance-a"
	unlockFirst()

	require.Empty(t, m.entries)
}

func TestKeyedMutexSameKey(t *testing.T) {
	const key = "instance"

	var m KeyedMutex[string]

	// lock key for the first time
	unlock := m.Lock(key)
	originalEntry := m.entries[key]

	acquired := make(chan struct{})
	shouldRelease := make(chan struct{})
	done := make(chan struct{})

	go func() {
		// lock key for the second time (this should block)
		unlock := m.Lock(key)

		// signal that the mutex has been acquired
		close(acquired)

		// wait for the signal to release the mutex
		<-shouldRelease
		unlock()

		// signal completion
		close(done)
	}()

	// Wait until the second caller has registered its reference.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		m.mu.Lock()
		defer m.mu.Unlock()

		assert.Equal(c, 2, m.entries[key].refs)
	}, 10*time.Second, 20*time.Millisecond)

	select {
	case <-acquired:
		t.Fatal("the same key was acquired by second caller while its mutex was still held by first caller")
	default:
	}

	// the first caller unlocks key
	unlock()

	// wait for the second caller to acquire the lock
	<-acquired

	m.mu.Lock()
	registered := m.entries[key]
	refs := m.entries[key].refs
	m.mu.Unlock()

	require.Same(t, originalEntry, registered, "a waiter must keep its original mutex registered")
	require.Equal(t, 1, refs)

	// signal the second caller that it should release the lock
	close(shouldRelease)

	// wait for second caller to complete
	<-done

	require.Empty(t, m.entries, "the last release must remove the entry")
}

func TestKeyedMutexConcurrentReuse(t *testing.T) {
	const (
		keys       = 4
		workers    = 32
		iterations = 200
	)

	var (
		m       KeyedMutex[int]
		active  [keys]atomic.Int32
		overlap atomic.Bool
		wg      sync.WaitGroup
	)

	start := make(chan struct{})

	for worker := range workers {
		wg.Go(func() {
			<-start

			for iteration := range iterations {
				key := (worker + iteration) % keys
				unlock := m.Lock(key)

				if active[key].Add(1) != 1 {
					overlap.Store(true)
				}

				// Give another caller a chance to contend for this key.
				runtime.Gosched()

				active[key].Add(-1)

				unlock()
			}
		})
	}

	close(start)

	wg.Wait()

	require.False(t, overlap.Load(), "multiple goroutines were able to lock the same key concurrently")
	require.Empty(t, m.entries)
}

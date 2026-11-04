/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package writebarrier

import (
	"sync"

	"k8s.io/apimachinery/pkg/types"
)

// WriteBarriers adds garbage collection for unused keys to WriteBarrier.
type WriteBarriers interface {
	// Begin keeps the passed key locked until the returned release func was called.
	Begin(key types.NamespacedName) (release func())

	// Seal seals the currently-active set of locks to key and returns a channel that
	// closes when they are done.
	Seal(key types.NamespacedName) <-chan struct{}

	// SealAll is Seal for all keys.
	SealAll() []<-chan struct{}
}

// NewWriteBarriers construct WriteBarriers. newBarrier is configurable for testing purposes only.
func NewWriteBarriers(newBarrier func() WriteBarrier) WriteBarriers {
	return &writeBarriers{
		data:       map[types.NamespacedName]*writeBarrierWithRefCounter{},
		newBarrier: newBarrier,
	}
}

type writeBarrierWithRefCounter struct {
	WriteBarrier
	inFlightWrites int
}

// writeBarriers holds one writeBarrier per key that has an in-flight write.
type writeBarriers struct {
	lock       sync.Mutex
	data       map[types.NamespacedName]*writeBarrierWithRefCounter
	newBarrier func() WriteBarrier
}

func (w *writeBarriers) Begin(key types.NamespacedName) func() {
	w.lock.Lock()
	defer w.lock.Unlock()

	barrier, exists := w.data[key]
	if !exists {
		barrier = &writeBarrierWithRefCounter{WriteBarrier: w.newBarrier()}
		w.data[key] = barrier
	}
	barrier.inFlightWrites++
	release := barrier.Begin()

	return func() {
		release()

		w.lock.Lock()
		defer w.lock.Unlock()
		barrier.inFlightWrites--
		if barrier.inFlightWrites == 0 {
			delete(w.data, key)
		}
	}
}

func (w *writeBarriers) Seal(key types.NamespacedName) <-chan struct{} {
	w.lock.Lock()
	defer w.lock.Unlock()

	barrier, exists := w.data[key]
	if !exists {
		return closedChannel
	}

	return barrier.Seal()
}

func (w *writeBarriers) SealAll() []<-chan struct{} {
	w.lock.Lock()
	defer w.lock.Unlock()

	result := make([]<-chan struct{}, 0, len(w.data))
	for _, barrier := range w.data {
		result = append(result, barrier.Seal())
	}

	return result
}

var closedChannel chan struct{}

func init() {
	closedChannel = make(chan struct{})
	close(closedChannel)
}

type WriteBarrier interface {
	Begin() (release func())
	Seal() <-chan struct{}
}

// NewWriteBarrier creates a new WriteBarrier
func NewWriteBarrier() WriteBarrier {
	return &keyWriteBarrier{previous: closedChannel}
}

// keyWriteBarrier allows to wait for a set of in-flight writes to finish.
type keyWriteBarrier struct {
	// lock must be held to access current or previous.
	lock sync.Mutex

	// current is the current write batch. It has a reference to the key write
	// barrier that it uses to delete itself once done.
	current *writeBatch

	// previous is closed once all previous write batches are done.
	previous <-chan struct{}
}

// Begin adds a write to the current batch, starting one if needed.
func (b *keyWriteBarrier) Begin() func() {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.current == nil {
		b.current = &writeBatch{barrier: b, done: make(chan struct{})}
	}
	b.current.inFlight++

	return b.current.release
}

func (b *keyWriteBarrier) Seal() <-chan struct{} {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.current == nil {
		return b.previous
	}

	// Create a new chan that blocks until both previous
	// and current are done.
	done := make(chan struct{})
	previous := b.previous
	b.previous = done

	current := b.current.done
	b.current = nil

	go func() {
		for _, c := range []<-chan struct{}{previous, current} {
			<-c
		}
		close(done)
	}()

	return done
}

type writeBatch struct {
	barrier  *keyWriteBarrier
	inFlight int
	done     chan struct{}
}

func (w *writeBatch) release() {
	w.barrier.lock.Lock()
	defer w.barrier.lock.Unlock()

	w.inFlight--
	if w.inFlight > 0 {
		return
	}

	close(w.done)
	if w.barrier.current == w {
		w.barrier.current = nil
	}
}

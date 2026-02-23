// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package internal

import (
	"cmp"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// sortableMutexSeq is a global sequence counter for the creation of new
// SortableMutex's with unique sequence numbers.
var sortableMutexSeq atomic.Uint64

// sortableMutex implements SortableMutex. Not exported as the only way to
// initialize it is via NewSortableMutex().
type sortableMutex struct {
	sync.Mutex
	seq             uint64
	acquireDuration time.Duration
}

func (s *sortableMutex) Lock() {
	start := time.Now()
	s.Mutex.Lock()
	s.acquireDuration = time.Since(start)
}

func (s *sortableMutex) Seq() uint64 { return s.seq }

func (s *sortableMutex) AcquireDuration() time.Duration { return s.acquireDuration }

// SortableMutex provides a Mutex that can be globally sorted with other
// sortable mutexes. This allows deadlock-safe locking of a set of mutexes
// as it guarantees consistent lock ordering.
type SortableMutex interface {
	sync.Locker
	Seq() uint64
	AcquireDuration() time.Duration // The amount of time it took to acquire the lock
}

// SortableMutexes is a set of mutexes that can be locked in a safe order.
// Once Lock() is called it must not be mutated!
type SortableMutexes []SortableMutex

// Lock sorts the mutexes, and then locks them in order. If any lock cannot be acquired,
// this will block while holding the locks with a lower sequence number.
func (s SortableMutexes) Lock() {
	slices.SortFunc(s, func(a, b SortableMutex) int { return cmp.Compare(a.Seq(), b.Seq()) })
	for _, mu := range s {
		mu.Lock()
	}
}

// Unlock locks the sorted set of mutexes locked by prior call to Lock().
func (s SortableMutexes) Unlock() {
	for _, mu := range s {
		mu.Unlock()
	}
}

func NewSortableMutex() SortableMutex {
	seq := sortableMutexSeq.Add(1)
	return &sortableMutex{
		seq: seq,
	}
}

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

// SortableMutex is a mutex with a globally unique sequence number. The sequence
// number allows SortableMutexes to lock a set of mutexes in a consistent order.
type SortableMutex struct {
	sync.Mutex
	seq             uint64
	acquireDuration time.Duration
}

func (s *SortableMutex) Lock() {
	start := time.Now()
	s.Mutex.Lock()
	s.acquireDuration = time.Since(start)
}

func (s *SortableMutex) Seq() uint64 { return s.seq }

func (s *SortableMutex) AcquireDuration() time.Duration { return s.acquireDuration }

// SortableMutexes is a set of mutexes that can be locked in a safe order.
// Once Lock() is called it must not be mutated!
type SortableMutexes []*SortableMutex

// Lock sorts the mutexes, and then locks them in order. If any lock cannot be acquired,
// this will block while holding the locks with a lower sequence number.
// Panics if the same mutex is included more than once.
func (s SortableMutexes) Lock() {
	slices.SortFunc(s, func(a, b *SortableMutex) int {
		aSeq, bSeq := a.Seq(), b.Seq()
		if aSeq == bSeq {
			panic("SortableMutexes: duplicate mutex")
		}
		return cmp.Compare(a.Seq(), b.Seq())
	})
	for _, mu := range s {
		mu.Lock()
	}
}

// Unlock unlocks the sorted set of mutexes locked by a prior call to Lock().
func (s SortableMutexes) Unlock() {
	for _, mu := range s {
		mu.Unlock()
	}
}

func NewSortableMutex() *SortableMutex {
	seq := sortableMutexSeq.Add(1)
	return &SortableMutex{
		seq: seq,
	}
}

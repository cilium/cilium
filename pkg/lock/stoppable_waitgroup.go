// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lock

import (
	"sync"
	"sync/atomic"
)

// A StoppableWaitGroup waits for a collection of goroutines to finish.
type StoppableWaitGroup struct {
	noopDone         chan struct{}
	noopAdd          chan struct{}
	i                *uint64
	wgOnce, doneOnce sync.Once
}

// NewStoppableWaitGroup returns a new StoppableWaitGroup. When the 'Stop' is
// executed, following 'Add()' calls won't have any effect.
func NewStoppableWaitGroup() *StoppableWaitGroup {
	return &StoppableWaitGroup{
		noopDone: make(chan struct{}),
		noopAdd:  make(chan struct{}),
		i:        func() *uint64 { i := uint64(0); return &i }(),
		wgOnce:   sync.Once{},
		doneOnce: sync.Once{},
	}
}

// Stop makes following 'Add()' to be considered a no-op.
// If all goroutines that have called Add also called Done, 'Wait()' will
// be immediately unblocked.
func (l *StoppableWaitGroup) Stop() {
	l.doneOnce.Do(func() {
		close(l.noopAdd)
		if atomic.LoadUint64(l.i) == 0 {
			l.wgOnce.Do(func() {
				close(l.noopDone)
			})
		}
	})
}

// Wait will return once all goroutines that have called Add also called
// Done and StoppableWaitGroup was stopped.
func (l *StoppableWaitGroup) Wait() {
	<-l.noopDone
}

// WaitChannel will return a channel that will be closed once all goroutines
// that have called Add also called Done and StoppableWaitGroup was stopped.
func (l *StoppableWaitGroup) WaitChannel() <-chan struct{} {
	return l.noopDone
}

// Add adds the go routine to the list of routines to that Wait() will have
// to wait before it returns.
// If the StoppableWaitGroup was stopped this will be a no-op.
func (l *StoppableWaitGroup) Add() {
	select {
	case <-l.noopAdd:
	default:
		atomic.AddUint64(l.i, 1)
	}
}

// Done will decrement the number of go routines the Wait() will have to wait
// before it returns.
// This function is a no-op once all go routines that have called 'Add()' have
// also called 'Done()' and the StoppableWaitGroup was stopped.
func (l *StoppableWaitGroup) Done() {
	select {
	case <-l.noopDone:
		return
	default:
		select {
		case <-l.noopAdd:
			a := atomic.AddUint64(l.i, ^uint64(0))
			if a == 0 {
				l.wgOnce.Do(func() {
					close(l.noopDone)
				})
			}
		default:
			atomic.AddUint64(l.i, ^uint64(0))
		}
	}
}

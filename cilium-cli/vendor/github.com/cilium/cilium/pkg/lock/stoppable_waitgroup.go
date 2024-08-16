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
	noopDone chan struct{}
	noopAdd  chan struct{}
	// i is the internal counter which can store tolerate negative values
	// as opposed the golang's library WaitGroup.
	i                  *int64
	doneOnce, stopOnce sync.Once
}

// NewStoppableWaitGroup returns a new StoppableWaitGroup. When the 'Stop' is
// executed, following 'Add()' calls won't have any effect.
func NewStoppableWaitGroup() *StoppableWaitGroup {
	return &StoppableWaitGroup{
		noopDone: make(chan struct{}),
		noopAdd:  make(chan struct{}),
		i:        func() *int64 { i := int64(0); return &i }(),
		doneOnce: sync.Once{},
		stopOnce: sync.Once{},
	}
}

// Stop makes following 'Add()' to be considered a no-op.
// If all goroutines that have called Add also called Done, 'Wait()' will
// be immediately unblocked.
func (l *StoppableWaitGroup) Stop() {
	l.stopOnce.Do(func() {
		// We will do an Add here so we can perform a Done after we close
		// the l.noopAdd channel.
		l.Add()
		close(l.noopAdd)
		// Calling Done() here so we know that in case 'l.i' will become zero
		// it will trigger a close of l.noopDone channel.
		l.Done()
	})
}

// Wait will return once all goroutines that have called Add also called
// Done and StoppableWaitGroup was stopped.
// Internally, Wait() returns once the internal counter becomes negative.
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
		atomic.AddInt64(l.i, 1)
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
			a := atomic.AddInt64(l.i, -1)
			if a <= 0 {
				l.doneOnce.Do(func() {
					close(l.noopDone)
				})
			}
		default:
			a := atomic.AddInt64(l.i, -1)
			select {
			// in case the channel was close while we where in this default
			// case we will need to check if 'a' is less than zero and close
			// l.noopDone channel.
			case <-l.noopAdd:
				if a <= 0 {
					l.doneOnce.Do(func() {
						close(l.noopDone)
					})
				}
			default:
			}
		}
	}
}

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

// +build !privileged_tests

package lock

import (
	"sync"
	"sync/atomic"

	. "gopkg.in/check.v1"
)

type StoppableWaitGroupSuite struct{}

var _ = Suite(&StoppableWaitGroupSuite{})

func (s *SemaphoredMutexSuite) TestAdd(c *C) {
	l := &StoppableWaitGroup{
		noopDone: make(chan struct{}),
		noopAdd:  make(chan struct{}),
		i:        func() *uint64 { i := uint64(0); return &i }(),
		wgOnce:   sync.Once{},
		doneOnce: sync.Once{},
	}

	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(1))
	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))
	close(l.noopAdd)
	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))
}

func (s *SemaphoredMutexSuite) TestDone(c *C) {
	l := &StoppableWaitGroup{
		noopDone: make(chan struct{}),
		noopAdd:  make(chan struct{}),
		i:        func() *uint64 { i := uint64(0); return &i }(),
		wgOnce:   sync.Once{},
		doneOnce: sync.Once{},
	}

	atomic.StoreUint64(l.i, 4)
	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(3))
	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))
	close(l.noopAdd)
	select {
	case _, ok := <-l.noopDone:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(1))
	select {
	case _, ok := <-l.noopDone:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(0))
	select {
	case _, ok := <-l.noopDone:
		c.Assert(ok, Equals, false)
	default:
		// channel should have been closed
		c.Assert(false, Equals, true)
	}

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(0))
}

func (s *SemaphoredMutexSuite) TestStop(c *C) {
	l := &StoppableWaitGroup{
		noopDone: make(chan struct{}),
		noopAdd:  make(chan struct{}),
		i:        func() *uint64 { i := uint64(0); return &i }(),
		wgOnce:   sync.Once{},
		doneOnce: sync.Once{},
	}

	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(1))
	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))
	l.Stop()
	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))
}

func (s *SemaphoredMutexSuite) TestWait(c *C) {
	l := &StoppableWaitGroup{
		noopDone: make(chan struct{}),
		noopAdd:  make(chan struct{}),
		i:        func() *uint64 { i := uint64(0); return &i }(),
		wgOnce:   sync.Once{},
		doneOnce: sync.Once{},
	}

	waitClosed := make(chan struct{})
	go func() {
		l.Wait()
		close(waitClosed)
	}()

	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(1))
	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))
	l.Stop()
	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(1))
	select {
	case _, ok := <-waitClosed:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(0))
	select {
	case _, ok := <-waitClosed:
		// channel should have been closed
		c.Assert(ok, Equals, false)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(0))
}

func (s *SemaphoredMutexSuite) TestWaitChannel(c *C) {
	l := &StoppableWaitGroup{
		noopDone: make(chan struct{}),
		noopAdd:  make(chan struct{}),
		i:        func() *uint64 { i := uint64(0); return &i }(),
		wgOnce:   sync.Once{},
		doneOnce: sync.Once{},
	}

	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(1))
	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))
	l.Stop()
	l.Add()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(2))

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(1))
	select {
	case _, ok := <-l.WaitChannel():
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(0))
	select {
	case _, ok := <-l.WaitChannel():
		// channel should have been closed
		c.Assert(ok, Equals, false)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadUint64(l.i), Equals, uint64(0))
}

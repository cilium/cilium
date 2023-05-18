// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/cilium/checkmate"
)

type StoppableWaitGroupSuite struct{}

var _ = Suite(&StoppableWaitGroupSuite{})

func (s *SemaphoredMutexSuite) TestAdd(c *C) {
	l := NewStoppableWaitGroup()

	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(1))
	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))
	close(l.noopAdd)
	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))
}

func (s *SemaphoredMutexSuite) TestDone(c *C) {
	l := NewStoppableWaitGroup()

	atomic.StoreInt64(l.i, 4)
	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(3))
	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))
	close(l.noopAdd)
	select {
	case _, ok := <-l.noopDone:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(1))
	select {
	case _, ok := <-l.noopDone:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(0))
	select {
	case _, ok := <-l.noopDone:
		c.Assert(ok, Equals, false)
	default:
		// channel should have been closed
		c.Assert(false, Equals, true)
	}

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(0))
}

func (s *SemaphoredMutexSuite) TestStop(c *C) {
	l := NewStoppableWaitGroup()

	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(1))
	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))
	l.Stop()
	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))
}

func (s *SemaphoredMutexSuite) TestWait(c *C) {
	l := NewStoppableWaitGroup()

	waitClosed := make(chan struct{})
	go func() {
		l.Wait()
		close(waitClosed)
	}()

	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(1))
	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))
	l.Stop()
	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(1))
	select {
	case _, ok := <-waitClosed:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(0))
	select {
	case _, ok := <-waitClosed:
		// channel should have been closed
		c.Assert(ok, Equals, false)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(0))
}

func (s *SemaphoredMutexSuite) TestWaitChannel(c *C) {
	l := NewStoppableWaitGroup()

	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(1))
	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))
	l.Stop()
	l.Add()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(2))

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(1))
	select {
	case _, ok := <-l.WaitChannel():
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(0))
	select {
	case _, ok := <-l.WaitChannel():
		// channel should have been closed
		c.Assert(ok, Equals, false)
	default:
	}

	l.Done()
	c.Assert(atomic.LoadInt64(l.i), Equals, int64(0))
}

func (s *SemaphoredMutexSuite) TestParallelism(c *C) {
	l := NewStoppableWaitGroup()

	// Use math/rand instead of pkg/rand to avoid a test import cycle which
	// go vet would complain about. Use the global default entropy source
	// rather than creating a new source to avoid concurrency issues.
	rand.Seed(time.Now().UnixNano())
	in := make(chan int)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case in <- rand.Intn(1 - 0):
			case <-stop:
				close(in)
				return
			}
		}
	}()
	adds := int64(0)
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			for a := range in {
				if a == 0 {
					atomic.AddInt64(&adds, 1)
					l.Add()
				} else {
					l.Done()
					atomic.AddInt64(&adds, -1)
				}
			}
		}()
	}

	time.Sleep(time.Duration(rand.Intn(3-0)) * time.Second)
	close(stop)
	wg.Wait()
	add := atomic.LoadInt64(&adds)
	for ; add != 0; add = atomic.LoadInt64(&adds) {
		switch {
		case add < 0:
			atomic.AddInt64(&adds, 1)
			l.Add()
		case add > 0:
			l.Done()
			atomic.AddInt64(&adds, -1)
		}
	}
	l.Stop()
	l.Wait()
}

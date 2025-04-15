// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAdd(t *testing.T) {
	l := NewStoppableWaitGroup()

	l.Add()
	require.Equal(t, int64(1), l.i.Load())
	l.Add()
	require.Equal(t, int64(2), l.i.Load())
	close(l.noopAdd)
	l.Add()
	require.Equal(t, int64(2), l.i.Load())
}

func TestDone(t *testing.T) {
	l := NewStoppableWaitGroup()

	l.i.Store(4)
	l.done()
	require.Equal(t, int64(3), l.i.Load())
	l.done()
	require.Equal(t, int64(2), l.i.Load())
	close(l.noopAdd)
	select {
	case _, ok := <-l.noopDone:
		// channel should not have been closed
		require.True(t, ok)
	default:
	}

	l.done()
	require.Equal(t, int64(1), l.i.Load())
	select {
	case _, ok := <-l.noopDone:
		// channel should not have been closed
		require.True(t, ok)
	default:
	}

	l.done()
	require.Equal(t, int64(0), l.i.Load())
	select {
	case _, ok := <-l.noopDone:
		require.False(t, ok)
	default:
		// channel should have been closed
		require.Fail(t, "channel should have been closed")
	}

	l.done()
	require.Equal(t, int64(0), l.i.Load())
}

func TestStop(t *testing.T) {
	l := NewStoppableWaitGroup()

	l.Add()
	require.Equal(t, int64(1), l.i.Load())
	l.Add()
	require.Equal(t, int64(2), l.i.Load())
	l.Stop()
	l.Add()
	require.Equal(t, int64(2), l.i.Load())
}

func TestWait(t *testing.T) {
	l := NewStoppableWaitGroup()

	waitClosed := make(chan struct{})
	go func() {
		l.Wait()
		close(waitClosed)
	}()

	l.Add()
	require.Equal(t, int64(1), l.i.Load())
	l.Add()
	require.Equal(t, int64(2), l.i.Load())
	l.Stop()
	l.Add()
	require.Equal(t, int64(2), l.i.Load())

	l.done()
	require.Equal(t, int64(1), l.i.Load())
	select {
	case _, ok := <-waitClosed:
		// channel should not have been closed
		require.True(t, ok)
	default:
	}

	l.done()
	require.Equal(t, int64(0), l.i.Load())
	select {
	case _, ok := <-waitClosed:
		// channel should have been closed
		require.False(t, ok)
	default:
	}

	l.done()
	require.Equal(t, int64(0), l.i.Load())
}

func TestWaitChannel(t *testing.T) {
	l := NewStoppableWaitGroup()

	done1 := l.Add()
	require.Equal(t, int64(1), l.i.Load())
	done2 := l.Add()
	require.Equal(t, int64(2), l.i.Load())
	l.Stop()
	done3 := l.Add()
	require.Equal(t, int64(2), l.i.Load())

	done1()
	require.Equal(t, int64(1), l.i.Load())
	select {
	case _, ok := <-l.WaitChannel():
		// channel should not have been closed
		require.True(t, ok)
	default:
	}

	// since add for done3 was done after stopping, this is a no-op
	done3()
	require.Equal(t, int64(1), l.i.Load())
	select {
	case _, ok := <-l.WaitChannel():
		// channel should not have been closed
		require.True(t, ok)
	default:
	}

	done2()
	require.Equal(t, int64(0), l.i.Load())
	select {
	case _, ok := <-l.WaitChannel():
		// channel should have been closed
		require.False(t, ok)
	default:
	}
}

func TestParallelism(t *testing.T) {
	l := NewStoppableWaitGroup()

	in := make(chan int)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case in <- rand.IntN(1 - 0):
			case <-stop:
				close(in)
				return
			}
		}
	}()
	var adds atomic.Int64
	var wg sync.WaitGroup
	wg.Add(10)
	for range 10 {
		go func() {
			defer wg.Done()
			for a := range in {
				if a == 0 {
					adds.Add(1)
					l.Add()
				} else {
					l.done()
					adds.Add(-1)
				}
			}
		}()
	}

	time.Sleep(time.Duration(rand.IntN(3-0)) * time.Second)
	close(stop)
	wg.Wait()
	for add := adds.Load(); add != 0; add = adds.Load() {
		switch {
		case add < 0:
			adds.Add(1)
			l.Add()
		case add > 0:
			l.done()
			adds.Add(-1)
		}
	}
	l.Stop()
	l.Wait()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rate

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
)

// Limiter is used to limit the number of operations done.
type Limiter struct {
	semaphore   *semaphore.Weighted
	burst       int64
	currWeights int64
	ticker      *time.Ticker
	cancelFunc  context.CancelFunc
	ctx         context.Context
}

// NewLimiter returns a new Limiter that allows events up to b tokens during
// the given interval.
// This Limiter has a different implementation from the 'x/time/rate's Limiter
// implementation. 'x/time/rate.Limiter' sends a constant stream of updates
// (at a rate of few dozen events per second) over the period of a N minutes
// which is the behavior of the token bucket algorithm. It is designed to
// flatten bursts in a signal to a fixed output rate.
// This rate.Limiter does the opposite of 'x/time/rate.Limiter'. It takes a
// somewhat fixed-rate stream of updates and turns it into a stream of
// controlled small bursts every N minutes.
func NewLimiter(interval time.Duration, b int64) *Limiter {
	ticker := time.NewTicker(interval)
	ctx, cancel := context.WithCancel(context.Background())
	l := &Limiter{
		semaphore:   semaphore.NewWeighted(b),
		burst:       b,
		ticker:      ticker,
		currWeights: 0,
		ctx:         ctx,
		cancelFunc:  cancel,
	}
	go func() {
		for {
			select {
			case <-ticker.C:
			case <-l.ctx.Done():
				return
			}
			currWeights := atomic.LoadInt64(&l.currWeights)
			atomic.AddInt64(&l.currWeights, -currWeights)
			l.semaphore.Release(currWeights)
		}
	}()
	return l
}

// Stop stops the internal components used for the rate limiter logic.
func (lim *Limiter) Stop() {
	lim.cancelFunc()
	lim.ticker.Stop()
}

func (lim *Limiter) assertAlive() {
	select {
	case <-lim.ctx.Done():
		panic("limiter misuse: Allow / Wait / WaitN called concurrently after Stop")
	default:
	}
}

// Allow is shorthand for AllowN(1).
func (lim *Limiter) Allow() bool {
	return lim.AllowN(1)
}

// AllowN returns true if it's possible to allow n tokens.
func (lim *Limiter) AllowN(n int64) bool {
	lim.assertAlive()
	acq := lim.semaphore.TryAcquire(n)
	if acq {
		atomic.AddInt64(&lim.currWeights, n)
		return true
	}
	return false
}

// Wait is shorthand for WaitN(ctx, 1).
func (lim *Limiter) Wait(ctx context.Context) error {
	return lim.WaitN(ctx, 1)
}

// WaitN acquires n tokens, blocking until resources are available or ctx is
// done. On success, returns nil. On failure, returns ctx.Err() and leaves the
// limiter unchanged.
//
// If ctx is already done, WaitN may still succeed without blocking.
func (lim *Limiter) WaitN(ctx context.Context, n int64) error {
	lim.assertAlive()
	if n > lim.burst {
		return fmt.Errorf("rate: Wait(n=%d) exceeds limiter's burst %d", n, lim.burst)
	}
	err := lim.semaphore.Acquire(ctx, n)
	if err != nil {
		return err
	}
	atomic.AddInt64(&lim.currWeights, n)
	return nil
}

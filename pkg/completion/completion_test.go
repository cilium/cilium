// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package completion

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	//logging.ToggleDebugLogs(true)
	TestingT(t)
}

type CompletionSuite struct{}

var _ = Suite(&CompletionSuite{})

const (
	TestTimeout      = 10 * time.Second
	WaitGroupTimeout = 250 * time.Millisecond
	CompletionDelay  = 250 * time.Millisecond
)

func (s *CompletionSuite) TestNoCompletion(c *C) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg := NewWaitGroup(ctx)

	// Wait should return immediately, since there are no completions.
	err = wg.Wait()
	c.Assert(err, IsNil)
}

func (s *CompletionSuite) TestCompletionBeforeWait(c *C) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletion()

	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	c.Assert(err, IsNil)
}

func (s *CompletionSuite) TestCompletionAfterWait(c *C) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletion()

	go func() {
		time.Sleep(CompletionDelay)
		comp.Complete(nil)
	}()

	// Wait should block until comp.Complete is called, then return nil.
	err = wg.Wait()
	c.Assert(err, IsNil)
}

func (s *CompletionSuite) TestCompletionBeforeAndAfterWait(c *C) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg := NewWaitGroup(ctx)

	comp1 := wg.AddCompletion()

	comp2 := wg.AddCompletion()

	comp1.Complete(nil)

	go func() {
		time.Sleep(CompletionDelay)
		comp2.Complete(nil)
	}()

	// Wait should block until comp2.Complete is called, then return nil.
	err = wg.Wait()
	c.Assert(err, IsNil)
}

func (s *CompletionSuite) TestCompletionTimeout(c *C) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wgCtx, cancel := context.WithTimeout(ctx, WaitGroupTimeout)
	defer cancel()
	wg := NewWaitGroup(wgCtx)

	comp := wg.AddCompletionWithCallback(func(err error) {
		// Callback gets called with context.DeadlineExceeded if the WaitGroup times out
		c.Assert(err, Equals, context.DeadlineExceeded)
	})

	// comp never completes.

	// Wait should block until wgCtx expires.
	err = wg.Wait()
	c.Assert(err, Not(IsNil))
	c.Assert(err, Equals, wgCtx.Err())

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete(nil)
}

func (s *CompletionSuite) TestCompletionMultipleCompleteCalls(c *C) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletion()

	// Complete is idempotent.
	comp.Complete(nil)
	comp.Complete(nil)
	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	c.Assert(err, IsNil)
}

func (s *CompletionSuite) TestCompletionWithCallback(c *C) {
	var err error
	var callbackCount int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletionWithCallback(func(err error) {
		if err == nil {
			callbackCount++
		}
	})

	// Complete is idempotent.
	comp.Complete(nil)
	comp.Complete(nil)
	comp.Complete(nil)

	// The callback is called exactly once.
	c.Assert(callbackCount, Equals, 1)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	c.Assert(err, IsNil)
}

func (s *CompletionSuite) TestCompletionWithCallbackError(c *C) {
	var err error
	var callbackCount, callbackCount2 int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	err1 := errors.New("Error1")
	err2 := errors.New("Error2")

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletionWithCallback(func(err error) {
		callbackCount++
		// Completion that completes with a failure gets the reason for the failure
		c.Assert(err, Equals, err1)
	})

	wg.AddCompletionWithCallback(func(err error) {
		callbackCount2++
		// When one completions fail the other completion callbacks
		// are called with context.Canceled
		c.Assert(err, Equals, context.Canceled)
	})

	// Complete is idempotent.
	comp.Complete(err1)
	comp.Complete(err2)
	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	c.Assert(err, Equals, err1)

	// The callbacks are called exactly once.
	c.Assert(callbackCount, Equals, 1)
	c.Assert(callbackCount2, Equals, 1)
}

func (s *CompletionSuite) TestCompletionWithCallbackOtherError(c *C) {
	var err error
	var callbackCount, callbackCount2 int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	err1 := errors.New("Error1")
	err2 := errors.New("Error2")

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	wg.AddCompletionWithCallback(func(err error) {
		callbackCount++
		c.Assert(err, Equals, context.Canceled)
	})

	comp2 := wg.AddCompletionWithCallback(func(err error) {
		callbackCount2++
		c.Assert(err, Equals, err2)
	})

	// Complete is idempotent.
	comp2.Complete(err2)
	comp2.Complete(err1)
	comp2.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	c.Assert(err, Equals, err2)

	// The callbacks are called exactly once.
	c.Assert(callbackCount, Equals, 1)
	c.Assert(callbackCount2, Equals, 1)
}

func (s *CompletionSuite) TestCompletionWithCallbackTimeout(c *C) {
	var err error
	var callbackCount int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wgCtx, cancel := context.WithTimeout(ctx, WaitGroupTimeout)
	defer cancel()
	wg := NewWaitGroup(wgCtx)

	comp := wg.AddCompletionWithCallback(func(err error) {
		if err == nil {
			callbackCount++
		}
		c.Assert(err, Equals, context.DeadlineExceeded)
	})

	// comp never completes.

	// Wait should block until wgCtx expires.
	err = wg.Wait()
	c.Assert(err, Not(IsNil))
	c.Assert(err, Equals, wgCtx.Err())

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete(nil)

	// The callback is only called with the error 'context.DeadlineExceeded'.
	c.Assert(callbackCount, Equals, 0)
}

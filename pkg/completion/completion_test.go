// Copyright 2018 Authors of Cilium
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

package completion

import (
	"errors"
	"testing"
	"time"

	"context"
	. "gopkg.in/check.v1"
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
	c.Assert(comp.Context(), Equals, wg.Context())

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
	c.Assert(comp.Context(), Equals, wg.Context())

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
	c.Assert(comp1.Context(), Equals, wg.Context())

	comp2 := wg.AddCompletion()
	c.Assert(comp2.Context(), Equals, wg.Context())

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

	comp := wg.AddCompletionWithCallback(func(err error) error {
		// Callback gets called with context.DeadlineExceeded if the WaitGroup times out
		c.Assert(err, Equals, context.DeadlineExceeded)
		return err
	})
	c.Assert(comp.Context(), Equals, wg.Context())

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
	c.Assert(comp.Context(), Equals, wg.Context())

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

	comp := wg.AddCompletionWithCallback(func(err error) error {
		if err == nil {
			callbackCount++
		}
		return nil
	})
	c.Assert(comp.Context(), Equals, wg.Context())

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

	comp := wg.AddCompletionWithCallback(func(err error) error {
		callbackCount++
		// Completion that completes with a failure gets the reason for the failure
		c.Assert(err, Equals, err1)
		// Non-nil return causes the whole WaitGroup to be cancelled
		return err
	})
	c.Assert(comp.Context(), Equals, wg.Context())

	comp2 := wg.AddCompletionWithCallback(func(err error) error {
		callbackCount2++
		// When one completions fail the other completion callbacks
		// are called with context.Canceled
		c.Assert(err, Equals, context.Canceled)
		return nil
	})
	c.Assert(comp2.Context(), Equals, wg.Context())

	// Complete is idempotent.
	comp.Complete(err1)
	comp.Complete(err2)
	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	c.Assert(err, Equals, context.Canceled)

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

	comp := wg.AddCompletionWithCallback(func(err error) error {
		callbackCount++
		c.Assert(err, Equals, context.Canceled)
		return nil
	})
	c.Assert(comp.Context(), Equals, wg.Context())

	comp2 := wg.AddCompletionWithCallback(func(err error) error {
		callbackCount2++
		c.Assert(err, Equals, err2)
		// Non-nil return causes the whole WaitGroup to be cancelled
		return err
	})
	c.Assert(comp2.Context(), Equals, wg.Context())

	// Complete is idempotent.
	comp2.Complete(err2)
	comp2.Complete(err1)
	comp2.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	c.Assert(err, Equals, context.Canceled)

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

	comp := wg.AddCompletionWithCallback(func(err error) error {
		if err == nil {
			callbackCount++
		}
		c.Assert(err, Equals, context.DeadlineExceeded)
		// If we make no effort to retry, we must return the error
		return err
	})
	c.Assert(comp.Context(), Equals, wg.Context())

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

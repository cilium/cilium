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
	c.Assert(comp.Context(), Equals, ctx)

	comp.Complete()

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
	c.Assert(comp.Context(), Equals, ctx)

	go func() {
		time.Sleep(CompletionDelay)
		comp.Complete()
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
	c.Assert(comp1.Context(), Equals, ctx)

	comp2 := wg.AddCompletion()
	c.Assert(comp2.Context(), Equals, ctx)

	comp1.Complete()

	go func() {
		time.Sleep(CompletionDelay)
		comp2.Complete()
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

	comp := wg.AddCompletion()
	c.Assert(comp.Context(), Equals, wgCtx)

	// comp never completes.

	// Wait should block until wgCtx expires.
	err = wg.Wait()
	c.Assert(err, Not(IsNil))
	c.Assert(err, Equals, wgCtx.Err())

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete()
}

func (s *CompletionSuite) TestCompletionMultipleCompleteCalls(c *C) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletion()
	c.Assert(comp.Context(), Equals, ctx)

	// Complete is idempotent.
	comp.Complete()
	comp.Complete()
	comp.Complete()

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

	comp := wg.AddCompletionWithCallback(func() { callbackCount++ })
	c.Assert(comp.Context(), Equals, ctx)

	// Complete is idempotent.
	comp.Complete()
	comp.Complete()
	comp.Complete()

	// The callback is called exactly once.
	c.Assert(callbackCount, Equals, 1)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	c.Assert(err, IsNil)
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

	comp := wg.AddCompletionWithCallback(func() { callbackCount++ })
	c.Assert(comp.Context(), Equals, wgCtx)

	// comp never completes.

	// Wait should block until wgCtx expires.
	err = wg.Wait()
	c.Assert(err, Not(IsNil))
	c.Assert(err, Equals, wgCtx.Err())

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete()

	// The callback is never called.
	c.Assert(callbackCount, Equals, 0)
}

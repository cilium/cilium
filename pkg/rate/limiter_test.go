// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rate

import (
	"context"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ControllerSuite struct{}

var _ = Suite(&ControllerSuite{})

func (b *ControllerSuite) TestLimiter(c *C) {
	l := NewLimiter(1*time.Second, 100)

	// We should be allowed to do this
	c.Assert(l.AllowN(100), Equals, true)
	// We shouldn't be allowed to get any left
	c.Assert(l.Allow(), Equals, false)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	err := l.WaitN(ctx, 100)
	cancel()
	// The limiter should have 100 spaces available within 1.5 seconds.
	c.Assert(err, IsNil)

	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = l.Wait(ctx)
	cancel()
	// The limiter should not have 1 spaces available within 100 milliseconds.
	c.Assert(err, Not(IsNil))

	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = l.WaitN(ctx, 101)
	cancel()
	// The limiter won't be able to handle that many burst requests.
	c.Assert(err, Not(IsNil))

	l.Stop()

	defer func() {
		r := recover()
		// Panic if we try to use the limiter after stopping it
		c.Assert(r, Equals, "limiter misuse: Allow / Wait / WaitN called concurrently after Stop")
	}()
	l.Allow()
}

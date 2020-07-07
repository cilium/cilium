// Copyright 2020 Authors of Cilium
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

package rate

import (
	"context"
	"testing"
	"time"

	. "gopkg.in/check.v1"
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

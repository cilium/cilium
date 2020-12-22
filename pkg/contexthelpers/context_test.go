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

package contexthelpers

import (
	"context"
	"testing"
	"time"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type ContextSuite struct{}

var _ = check.Suite(&ContextSuite{})

func (b *ContextSuite) TestConditionalTimeoutContext(c *check.C) {
	ctx, cancel, ch := NewConditionalTimeoutContext(context.Background(), 10*time.Millisecond)
	c.Assert(ctx, check.Not(check.IsNil))
	c.Assert(cancel, check.Not(check.IsNil))
	c.Assert(ch, check.Not(check.IsNil))

	// validate that the context is being cancelled due to the 10
	// millisecond timeout specified
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		c.Errorf("conditional timeout was not triggered")
	}

	ctx, cancel, ch = NewConditionalTimeoutContext(context.Background(), 10*time.Millisecond)
	// report success via the channel
	ch <- true
	close(ch)

	// validate that the context is not being cancelled as success has been
	// reported
	select {
	case <-ctx.Done():
		c.Errorf("context cancelled despite reporting success")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()

	_, _, ch = NewConditionalTimeoutContext(context.Background(), 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	// validate that sending to success channel does not deadlock after the timeout
	ch <- false
}

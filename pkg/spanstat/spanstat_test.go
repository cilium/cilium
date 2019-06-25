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

// +build !privileged_tests

package spanstat

import (
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type SpanStatTestSuite struct{}

var _ = Suite(&SpanStatTestSuite{})

func (s *SpanStatTestSuite) TestSpanStatStart(c *C) {
	span1 := Start()
	span1.EndError(nil)
	c.Assert(span1.Total(), Not(Equals), time.Duration(0))
}

func (s *SpanStatTestSuite) TestSpanStat(c *C) {
	span1 := SpanStat{}

	// no spans measured yet
	c.Assert(span1.Total(), Equals, time.Duration(0))
	c.Assert(span1.SuccessTotal(), Equals, time.Duration(0))
	c.Assert(span1.FailureTotal(), Equals, time.Duration(0))

	// End() without Start()
	span1.End(true)
	c.Assert(span1.Total(), Equals, time.Duration(0))
	c.Assert(span1.SuccessTotal(), Equals, time.Duration(0))
	c.Assert(span1.FailureTotal(), Equals, time.Duration(0))

	// Start() but no end yet
	span1.Start()
	c.Assert(span1.Total(), Equals, time.Duration(0))
	c.Assert(span1.SuccessTotal(), Equals, time.Duration(0))
	c.Assert(span1.FailureTotal(), Equals, time.Duration(0))

	// First span measured with End()
	span1.End(true)
	spanTotal1 := span1.Total()
	spanSuccessTotal1 := span1.SuccessTotal()
	spanFailureTotal1 := span1.FailureTotal()
	c.Assert(span1.Total(), Not(Equals), time.Duration(0))
	c.Assert(span1.SuccessTotal(), Not(Equals), time.Duration(0))
	c.Assert(span1.FailureTotal(), Equals, time.Duration(0))
	c.Assert(span1.Total(), Equals, span1.SuccessTotal()+span1.FailureTotal())

	// End() without a prior Start(), no change
	span1.End(true)
	c.Assert(span1.Total(), Equals, spanTotal1)
	c.Assert(span1.SuccessTotal(), Equals, spanSuccessTotal1)
	c.Assert(span1.FailureTotal(), Equals, spanFailureTotal1)

	span1.Start()
	span1.End(false)
	c.Assert(span1.Total(), Not(Equals), spanTotal1)
	c.Assert(span1.SuccessTotal(), Equals, spanSuccessTotal1)
	c.Assert(span1.FailureTotal(), Not(Equals), spanFailureTotal1)
	c.Assert(span1.Total(), Equals, span1.SuccessTotal()+span1.FailureTotal())

	span1.Reset()
	c.Assert(span1.Total(), Equals, time.Duration(0))
	c.Assert(span1.SuccessTotal(), Equals, time.Duration(0))
	c.Assert(span1.FailureTotal(), Equals, time.Duration(0))
}

func (s *SpanStatTestSuite) TestSpanStatSeconds(c *C) {
	span1 := Start()
	c.Assert(span1.Seconds(), Not(Equals), float64(0))
}

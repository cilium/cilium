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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

func (s *SpanStatTestSuite) TestSpanStatSecondsRaceCondition(c *C) {
	span1 := Start()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(span *SpanStat) {
			c.Assert(span1.Seconds(), Not(Equals), float64(0))
		}(span1)
	}
	wg.Done()
}

func TestSpanStatRaceCondition(t *testing.T) {
	type fields struct {
		runFunc func(span *SpanStat) float64
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "End function",
			fields: fields{
				runFunc: func(span *SpanStat) float64 {
					return span.End(true).Seconds()
				},
			},
		},
		{
			name: "EndError function",
			fields: fields{
				runFunc: func(span *SpanStat) float64 {
					return span.EndError(fmt.Errorf("dummy error")).Seconds()
				},
			},
		},
		{
			name: "Seconds function",
			fields: fields{
				runFunc: func(span *SpanStat) float64 {
					return span.Seconds()
				},
			},
		},
		{
			name: "Total function",
			fields: fields{
				runFunc: func(span *SpanStat) float64 {
					return span.Total().Seconds() + 1
				},
			},
		},
		{
			name: "FailureTotal function",
			fields: fields{
				runFunc: func(span *SpanStat) float64 {
					return span.FailureTotal().Seconds() + 1
				},
			},
		},
		{
			name: "SuccessTotal function",
			fields: fields{
				runFunc: func(span *SpanStat) float64 {
					return span.SuccessTotal().Seconds() + 1
				},
			},
		},
		{
			name: "Reset function",
			fields: fields{
				runFunc: func(span *SpanStat) float64 {
					span.Reset()
					return 1
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := Start()
			var wg sync.WaitGroup

			for i := 0; i < 5; i++ {
				wg.Add(1)
				go func(span *SpanStat) {
					assert.NotEqual(t, tt.fields.runFunc(span), float64(0))
				}(span)
			}
			wg.Done()
		})
	}

}

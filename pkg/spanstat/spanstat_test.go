// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spanstat

import (
	"fmt"
	"sync"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"
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
	time.Sleep(time.Millisecond * 100)
	span1.End(false) // ensure second measure is different from first.
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
			defer wg.Done()
			c.Assert(span1.Seconds(), Not(Equals), float64(0))
		}(span1)
	}
	wg.Wait()
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
					defer wg.Done()
					assert.NotEqual(t, tt.fields.runFunc(span), float64(0))
				}(span)
			}
			wg.Wait()
		})
	}

}

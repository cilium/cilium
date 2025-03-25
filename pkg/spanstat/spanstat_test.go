// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spanstat

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSpanStatStart(t *testing.T) {
	span1 := Start()
	span1.EndError(nil)
	require.NotEqual(t, time.Duration(0), span1.Total())
}

func TestSpanStat(t *testing.T) {
	span1 := SpanStat{}

	// no spans measured yet
	require.Equal(t, time.Duration(0), span1.Total())
	require.Equal(t, time.Duration(0), span1.SuccessTotal())
	require.Equal(t, time.Duration(0), span1.FailureTotal())

	// End() without Start()
	span1.End(true)
	require.Equal(t, time.Duration(0), span1.Total())
	require.Equal(t, time.Duration(0), span1.SuccessTotal())
	require.Equal(t, time.Duration(0), span1.FailureTotal())

	// Start() but no end yet
	span1.Start()
	require.Equal(t, time.Duration(0), span1.Total())
	require.Equal(t, time.Duration(0), span1.SuccessTotal())
	require.Equal(t, time.Duration(0), span1.FailureTotal())

	// First span measured with End()
	span1.End(true)
	spanTotal1 := span1.Total()
	spanSuccessTotal1 := span1.SuccessTotal()
	spanFailureTotal1 := span1.FailureTotal()
	require.NotEqual(t, time.Duration(0), span1.Total())
	require.NotEqual(t, time.Duration(0), span1.SuccessTotal())
	require.Equal(t, time.Duration(0), span1.FailureTotal())
	require.Equal(t, span1.Total(), span1.SuccessTotal()+span1.FailureTotal())

	// End() without a prior Start(), no change
	span1.End(true)
	require.Equal(t, spanTotal1, span1.Total())
	require.Equal(t, spanSuccessTotal1, span1.SuccessTotal())
	require.Equal(t, spanFailureTotal1, span1.FailureTotal())

	span1.Start()
	time.Sleep(time.Millisecond * 100)
	span1.End(false) // ensure second measure is different from first.
	require.NotEqual(t, spanTotal1, span1.Total())
	require.Equal(t, spanSuccessTotal1, span1.SuccessTotal())
	require.NotEqual(t, spanFailureTotal1, span1.FailureTotal())
	require.Equal(t, span1.Total(), span1.SuccessTotal()+span1.FailureTotal())

	span1.Reset()
	require.Equal(t, time.Duration(0), span1.Total())
	require.Equal(t, time.Duration(0), span1.SuccessTotal())
	require.Equal(t, time.Duration(0), span1.FailureTotal())
}

func TestSpanStatSeconds(t *testing.T) {
	span1 := Start()
	require.NotEqual(t, float64(0), span1.Seconds())
}

func TestSpanStatSecondsRaceCondition(t *testing.T) {
	span1 := Start()
	var wg sync.WaitGroup

	for range 10 {
		wg.Add(1)
		go func(span *SpanStat) {
			defer wg.Done()
			require.NotEqual(t, float64(0), span1.Seconds())
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

			for range 5 {
				wg.Add(1)
				go func(span *SpanStat) {
					defer wg.Done()
					require.NotEqual(t, float64(0), tt.fields.runFunc(span))
				}(span)
			}
			wg.Wait()
		})
	}
}

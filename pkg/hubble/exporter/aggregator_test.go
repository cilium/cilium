// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	timestamp "google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/parser/fieldaggregate"
	"github.com/cilium/cilium/pkg/time"
)

func TestGenerateAggregationKey(t *testing.T) {
	tests := []struct {
		name       string
		fieldPaths []string
		flow       *flowpb.Flow
	}{
		{
			name:       "basic fields",
			fieldPaths: []string{"destination.pod_name", "verdict"},
			flow: &flowpb.Flow{
				Verdict: flowpb.Verdict_FORWARDED,
				Destination: &flowpb.Endpoint{
					PodName: "dest-pod",
				},
			},
		},
		{
			name:       "empty fields",
			fieldPaths: []string{},
			flow: &flowpb.Flow{
				Verdict: flowpb.Verdict_FORWARDED,
			},
		},
		{
			name:       "missing nested field",
			fieldPaths: []string{"source.pod_name"},
			flow: &flowpb.Flow{
				Source: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fieldMask, err := fieldmaskpb.New(&flowpb.Flow{}, tt.fieldPaths...)
			require.NoError(t, err)

			fieldAgg, err := fieldaggregate.New(fieldMask)
			require.NoError(t, err)

			aggregator := NewAggregatorWithFields(fieldAgg, hivetest.Logger(t))

			processedFlow := &flowpb.Flow{}
			fieldAgg.Copy(processedFlow.ProtoReflect(), tt.flow.ProtoReflect())

			key := aggregator.generateAggregationKey(processedFlow)

			if len(tt.fieldPaths) == 0 {
				assert.Empty(t, string(key))
			} else {
				assert.NotEmpty(t, string(key))
			}

			processedFlow2 := &flowpb.Flow{}
			fieldAgg.Copy(processedFlow2.ProtoReflect(), tt.flow.ProtoReflect())
			key2 := aggregator.generateAggregationKey(processedFlow2)
			assert.Equal(t, key, key2, "Keys should be deterministic")
		})
	}
}

func TestAggregateAdd(t *testing.T) {
	t.Run("basic aggregation", func(t *testing.T) {
		fieldMask, err := fieldmaskpb.New(&flowpb.Flow{}, "verdict")
		require.NoError(t, err)

		fieldAgg, err := fieldaggregate.New(fieldMask)
		require.NoError(t, err)

		aggregator := NewAggregatorWithFields(fieldAgg, hivetest.Logger(t))

		// Add ingress, egress, and unknown direction flows with same verdict
		aggregator.Add(&v1.Event{
			Event: &flowpb.Flow{
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
			},
		})
		aggregator.Add(&v1.Event{
			Event: &flowpb.Flow{
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
			},
		})
		aggregator.Add(&v1.Event{
			Event: &flowpb.Flow{
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN,
			},
		})

		// Verify aggregation
		assert.Len(t, aggregator.m, 1)

		// Create the expected key for verdict=FORWARDED
		expectedFlow := &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}
		expectedKey := aggregator.generateAggregationKey(expectedFlow)

		value, exists := aggregator.m[expectedKey]
		require.True(t, exists, "Expected aggregation key should exist")
		assert.Equal(t, 1, value.IngressFlowCount)
		assert.Equal(t, 1, value.EgressFlowCount)
		assert.Equal(t, 1, value.UnknownDirectionFlowCount)
	})

	t.Run("nil event", func(t *testing.T) {
		aggregator := NewAggregator(hivetest.Logger(t))
		aggregator.Add(&v1.Event{Event: nil})
		assert.Empty(t, aggregator.m)
	})

	t.Run("non-flow event", func(t *testing.T) {
		aggregator := NewAggregator(hivetest.Logger(t))
		aggregator.Add(&v1.Event{Event: &observerpb.AgentEvent{}})
		assert.Empty(t, aggregator.m)
	})

	t.Run("unknown direction flows", func(t *testing.T) {
		fieldMask, err := fieldmaskpb.New(&flowpb.Flow{}, "verdict")
		require.NoError(t, err)

		fieldAgg, err := fieldaggregate.New(fieldMask)
		require.NoError(t, err)

		aggregator := NewAggregatorWithFields(fieldAgg, hivetest.Logger(t))

		// Add multiple unknown direction flows
		aggregator.Add(&v1.Event{
			Event: &flowpb.Flow{
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN,
			},
		})
		aggregator.Add(&v1.Event{
			Event: &flowpb.Flow{
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN,
			},
		})

		// Verify aggregation
		assert.Len(t, aggregator.m, 1)

		// Create the expected key for verdict=FORWARDED
		expectedFlow := &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}
		expectedKey := aggregator.generateAggregationKey(expectedFlow)

		value, exists := aggregator.m[expectedKey]
		require.True(t, exists, "Expected aggregation key should exist")
		assert.Equal(t, 0, value.IngressFlowCount)
		assert.Equal(t, 0, value.EgressFlowCount)
		assert.Equal(t, 2, value.UnknownDirectionFlowCount)
	})
}

func TestAggregateComplexScenario(t *testing.T) {
	fieldMask, err := fieldmaskpb.New(&flowpb.Flow{}, "destination.pod_name", "source.pod_name")
	require.NoError(t, err)

	fieldAgg, err := fieldaggregate.New(fieldMask)
	require.NoError(t, err)

	aggregator := NewAggregatorWithFields(fieldAgg, hivetest.Logger(t))

	for _, event := range getEventList() {
		aggregator.Add(event)
	}

	assert.Len(t, aggregator.m, 1)

	for _, value := range aggregator.m {
		assert.Equal(t, 1, value.IngressFlowCount)
		assert.Equal(t, 2, value.EgressFlowCount)
		assert.Equal(t, 0, value.UnknownDirectionFlowCount)
		assert.NotNil(t, value.ProcessedFlow)
	}
}

func TestAggregatorRunFunction(t *testing.T) {
	t.Run("processes events and resets map", func(t *testing.T) {
		buf := &bytesWriteCloser{bytes.Buffer{}}
		log := hivetest.Logger(t)

		opts := DefaultOptions
		opts.newWriterFunc = func() (io.WriteCloser, error) {
			return buf, nil
		}

		err := WithAggregationInterval(100 * time.Millisecond)(&opts)
		require.NoError(t, err)
		err = WithFieldAggregate([]string{"verdict"})(&opts)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		exporter, err := newExporter(ctx, log, opts)
		require.NoError(t, err)
		defer exporter.Stop()

		exporter.a.Add(getEventList()[0])

		// Wait for Run cycle
		time.Sleep(200 * time.Millisecond)

		// Verify map was reset
		exporter.a.mu.RLock()
		mapSize := len(exporter.a.m)
		exporter.a.mu.RUnlock()

		assert.Equal(t, 0, mapSize)
		assert.NotEmpty(t, buf.String())
	})

	t.Run("handles empty aggregator", func(t *testing.T) {
		buf := &bytesWriteCloser{bytes.Buffer{}}
		log := hivetest.Logger(t)

		opts := DefaultOptions
		opts.newWriterFunc = func() (io.WriteCloser, error) {
			return buf, nil
		}

		err := WithAggregationInterval(100 * time.Millisecond)(&opts)
		require.NoError(t, err)
		err = WithFieldAggregate([]string{"verdict"})(&opts)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		exporter, err := newExporter(ctx, log, opts)
		require.NoError(t, err)
		defer exporter.Stop()

		time.Sleep(150 * time.Millisecond)
		assert.Empty(t, buf.String())
	})

	t.Run("handles encoder errors", func(t *testing.T) {
		buf := &bytesWriteCloser{bytes.Buffer{}}
		log := hivetest.Logger(t)

		opts := DefaultOptions
		opts.newWriterFunc = func() (io.WriteCloser, error) {
			return buf, nil
		}

		err := WithAggregationInterval(100 * time.Millisecond)(&opts)
		require.NoError(t, err)
		err = WithFieldAggregate([]string{"verdict"})(&opts)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		exporter, err := newExporter(ctx, log, opts)
		require.NoError(t, err)
		defer exporter.Stop()

		exporter.a.Add(getEventList()[0])
		time.Sleep(150 * time.Millisecond)

		// Map should still be reset even on error
		exporter.a.mu.RLock()
		mapSize := len(exporter.a.m)
		exporter.a.mu.RUnlock()

		assert.Equal(t, 0, mapSize)
	})
}

func TestAsyncProcessingEdgeCases(t *testing.T) {

	t.Run("context cancellation during run loop", func(t *testing.T) {
		buf := &bytesWriteCloser{bytes.Buffer{}}
		log := hivetest.Logger(t)

		opts := DefaultOptions
		opts.newWriterFunc = func() (io.WriteCloser, error) {
			return buf, nil
		}
		err := WithAggregationInterval(100 * time.Millisecond)(&opts)
		require.NoError(t, err)
		err = WithFieldAggregate([]string{"verdict"})(&opts)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())

		exporter, err := newExporter(ctx, log, opts)
		require.NoError(t, err)

		// Add event
		exporter.a.Add(getEventList()[0])

		// Cancel context immediately to test race condition
		cancel()
		time.Sleep(50 * time.Millisecond)

		// Stop should not hang
		err = exporter.Stop()
		assert.NoError(t, err)
	})

	t.Run("ticker cleanup on context done", func(t *testing.T) {
		buf := &bytesWriteCloser{bytes.Buffer{}}
		log := hivetest.Logger(t)

		opts := DefaultOptions
		opts.newWriterFunc = func() (io.WriteCloser, error) {
			return buf, nil
		}

		err := WithAggregationInterval(100 * time.Millisecond)(&opts)
		require.NoError(t, err)
		err = WithFieldAggregate([]string{"verdict"})(&opts)
		require.NoError(t, err)

		// Record baseline goroutine count
		runtime.GC() // Force garbage collection to clean up any existing goroutines
		time.Sleep(10 * time.Millisecond)
		baselineGoroutines := runtime.NumGoroutine()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		exporter, err := newExporter(ctx, log, opts)
		require.NoError(t, err)
		defer exporter.Stop()

		// Wait for context to timeout - should clean up properly
		time.Sleep(100 * time.Millisecond)

		// Verify no goroutine leak - allow small variance for test framework goroutines
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		finalGoroutines := runtime.NumGoroutine()
		assert.LessOrEqual(t, finalGoroutines, baselineGoroutines+1)
	})
}
func getEventList() []*v1.Event {
	return []*v1.Event{
		{
			Event: &flowpb.Flow{
				Time:    &timestamp.Timestamp{Seconds: 1692369601},
				Verdict: flowpb.Verdict_FORWARDED,
				Source: &flowpb.Endpoint{
					Namespace: "default",
					PodName:   "src-pod1",
				},
				Destination: &flowpb.Endpoint{
					Namespace: "default",
					PodName:   "dest-pod1",
				},
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
			},
		},
		{
			Event: &flowpb.Flow{
				Time:    &timestamp.Timestamp{Seconds: 1692369604},
				Verdict: flowpb.Verdict_FORWARDED,
				Source: &flowpb.Endpoint{
					Namespace: "default",
					PodName:   "src-pod1",
				},
				Destination: &flowpb.Endpoint{
					Namespace: "default",
					PodName:   "dest-pod1",
				},
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
			},
		},
		{
			Event: &flowpb.Flow{
				Time:    &timestamp.Timestamp{Seconds: 1692369604},
				Verdict: flowpb.Verdict_FORWARDED,
				Source: &flowpb.Endpoint{
					Namespace: "default",
					PodName:   "src-pod1",
				},
				Destination: &flowpb.Endpoint{
					Namespace: "default",
					PodName:   "dest-pod1",
				},
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
			},
		},
	}
}

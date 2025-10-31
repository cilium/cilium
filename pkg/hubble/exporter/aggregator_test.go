// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"context"
	"io"
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
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

// testAggregatorOptions creates standard options for aggregator testing
func testAggregatorOptions(buf *bytesWriteCloser) Options {
	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}
	return opts
}

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
		opts := testAggregatorOptions(buf)

		err := WithAggregationInterval(100 * time.Millisecond)(&opts)
		require.NoError(t, err)
		err = WithFieldAggregate([]string{"verdict"})(&opts)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		exporter, err := newExporter(ctx, hivetest.Logger(t), opts)
		require.NoError(t, err)
		defer exporter.Stop()

		exporter.aggregator.Add(getEventList()[0])

		// Wait for Run cycle to process and reset map
		assert.Eventually(t, func() bool {
			exporter.aggregator.aggregator.mu.RLock()
			mapSize := len(exporter.aggregator.aggregator.m)
			exporter.aggregator.aggregator.mu.RUnlock()
			return mapSize == 0
		}, timeout, tick)

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

		exporter.aggregator.Add(getEventList()[0])

		// Wait for aggregation cycle to process and reset map even on error
		assert.Eventually(t, func() bool {
			exporter.aggregator.aggregator.mu.RLock()
			mapSize := len(exporter.aggregator.aggregator.m)
			exporter.aggregator.aggregator.mu.RUnlock()
			return mapSize == 0
		}, timeout, tick)
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
		defer exporter.Stop()

		// Add event
		exporter.aggregator.Add(getEventList()[0])

		// Cancel context immediately to test race condition
		cancel()
	})

	t.Run("ticker cleanup on context done", func(t *testing.T) {
		defer testutils.GoleakVerifyNone(t)

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

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		exporter, err := newExporter(ctx, log, opts)
		require.NoError(t, err)
		defer exporter.Stop()

		// Wait for context timeout to trigger cleanup, then let goleak verify no leaks
		<-ctx.Done()
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

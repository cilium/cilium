// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
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

// failingEncoder is a test encoder that always returns an error.
type failingEncoder struct{}

func (f *failingEncoder) Encode(event any) error {
	return io.ErrClosedPipe // Simulate encoder failure
}

// testAggregatorOptions creates standard options for aggregator testing.
func testAggregatorOptions(buf *bytesWriteCloser) Options {
	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}
	return opts
}

// testExporterWithAggregation creates an exporter with aggregation enabled for testing.
func testExporterWithAggregation(t *testing.T, interval time.Duration, fields []string) (*exporter, *bytesWriteCloser) {
	buf := &bytesWriteCloser{bytes.Buffer{}}
	opts := testAggregatorOptions(buf)

	err := WithAggregationInterval(interval)(&opts)
	require.NoError(t, err)
	err = WithFieldAggregate(fields)(&opts)
	require.NoError(t, err)

	exporter, err := newExporter(hivetest.Logger(t), opts)
	require.NoError(t, err)

	return exporter, buf
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

			processedFlow := &flowpb.Flow{}
			fieldAgg.Copy(processedFlow.ProtoReflect(), tt.flow.ProtoReflect())

			key := generateAggregationKey(processedFlow)

			if len(tt.fieldPaths) == 0 {
				assert.Empty(t, string(key))
			} else {
				assert.NotEmpty(t, string(key))
			}

			processedFlow2 := &flowpb.Flow{}
			fieldAgg.Copy(processedFlow2.ProtoReflect(), tt.flow.ProtoReflect())
			key2 := generateAggregationKey(processedFlow2)
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

		// Add ingress, egress, and unknown direction flows with same verdict.
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

		// Verify aggregation.
		assert.Len(t, aggregator.m, 1)

		// Create the expected key for verdict=FORWARDED.
		expectedFlow := &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}
		expectedKey := generateAggregationKey(expectedFlow)

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

		// Add multiple unknown direction flows.
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

		// Verify aggregation.
		assert.Len(t, aggregator.m, 1)

		// Create the expected key for verdict=FORWARDED.
		expectedFlow := &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}
		expectedKey := generateAggregationKey(expectedFlow)

		value, exists := aggregator.m[expectedKey]
		require.True(t, exists, "Expected aggregation key should exist")
		assert.Equal(t, 0, value.IngressFlowCount)
		assert.Equal(t, 0, value.EgressFlowCount)
		assert.Equal(t, 2, value.UnknownDirectionFlowCount)
	})

	t.Run("multi-field aggregation", func(t *testing.T) {
		fieldMask, err := fieldmaskpb.New(&flowpb.Flow{}, "destination.pod_name", "source.pod_name")
		require.NoError(t, err)

		fieldAgg, err := fieldaggregate.New(fieldMask)
		require.NoError(t, err)

		aggregator := NewAggregatorWithFields(fieldAgg, hivetest.Logger(t))

		// Use the same events as other tests for consistency.
		for _, event := range getEventList() {
			aggregator.Add(event)
		}

		// All events have same source/destination pods, so should create 1 aggregation.
		assert.Len(t, aggregator.m, 1)

		// Find and verify the aggregation (src-pod1 -> dest-pod1).
		expectedFlow := &flowpb.Flow{
			Source: &flowpb.Endpoint{
				Namespace: "default",
				PodName:   "src-pod1",
			},
			Destination: &flowpb.Endpoint{
				Namespace: "default",
				PodName:   "dest-pod1",
			},
		}
		processedFlow := &flowpb.Flow{}
		fieldAgg.Copy(processedFlow.ProtoReflect(), expectedFlow.ProtoReflect())
		expectedKey := generateAggregationKey(processedFlow)

		value, exists := aggregator.m[expectedKey]
		require.True(t, exists, "Aggregation key should exist")
		assert.Equal(t, 1, value.IngressFlowCount)
		assert.Equal(t, 2, value.EgressFlowCount)
		assert.Equal(t, 0, value.UnknownDirectionFlowCount)
		assert.NotNil(t, value.ProcessedFlow)
	})

	t.Run("oneof field mask with mixed protocols", func(t *testing.T) {
		// Test that field mask correctly handles oneof variants (e.g., TCP vs UDP, HTTP vs DNS),
		// when multiple variants are specified in the field mask.
		fieldMask, err := fieldmaskpb.New(&flowpb.Flow{},
			"source.namespace",
			"l4.TCP.destination_port",
			"l4.UDP.destination_port", // Both TCP and UDP specified.
			"l7.http.code",
			"l7.dns.rcode", // Both HTTP and DNS specified.
		)
		require.NoError(t, err)

		fieldAgg, err := fieldaggregate.New(fieldMask)
		require.NoError(t, err)

		aggregator := NewAggregatorWithFields(fieldAgg, hivetest.Logger(t))

		// Create 2 identical TCP+HTTP flows.
		flow1 := &flowpb.Flow{
			Source: &flowpb.Endpoint{Namespace: "default"},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{
						SourcePort:      33001,
						DestinationPort: 443,
					},
				},
			},
			L7: &flowpb.Layer7{
				Type: flowpb.L7FlowType_RESPONSE,
				Record: &flowpb.Layer7_Http{
					Http: &flowpb.HTTP{
						Code: 200,
					},
				},
			},
			TrafficDirection: flowpb.TrafficDirection_INGRESS,
		}

		flow2 := &flowpb.Flow{
			Source: &flowpb.Endpoint{Namespace: "default"},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{
						SourcePort:      33002, // Different source port (not in mask).
						DestinationPort: 443,
					},
				},
			},
			L7: &flowpb.Layer7{
				Type: flowpb.L7FlowType_RESPONSE,
				Record: &flowpb.Layer7_Http{
					Http: &flowpb.HTTP{
						Code: 200,
					},
				},
			},
			TrafficDirection: flowpb.TrafficDirection_INGRESS,
		}

		aggregator.Add(&v1.Event{Event: flow1})
		aggregator.Add(&v1.Event{Event: flow2})

		// Should have exactly 1 aggregation (both flows are identical after masking).
		// Previously without the oneof fix, this would create 2 aggregations because
		// the field mask would create spurious UDP and DNS structures.
		assert.Len(t, aggregator.m, 1, "should have exactly 1 aggregation, not one per spurious oneof variant")

		for _, value := range aggregator.m {
			assert.Equal(t, 2, value.IngressFlowCount)
			assert.Equal(t, 0, value.EgressFlowCount)
		}
	})
}

func TestAggregateTimeEnrichment(t *testing.T) {

	t.Run("time enriched despite not in fieldmask", func(t *testing.T) {
		// Field Aggregate excludes time, but the processed flow is enriched anyway.
		fieldMask, err := fieldmaskpb.New(&flowpb.Flow{}, "verdict")
		require.NoError(t, err)

		fieldAgg, err := fieldaggregate.New(fieldMask)
		require.NoError(t, err)

		aggregator := NewAggregatorWithFields(fieldAgg, hivetest.Logger(t))
		testTimestamp := &timestamp.Timestamp{Seconds: 1692369601, Nanos: 123456789}
		aggregator.Add(&v1.Event{
			Event: &flowpb.Flow{
				Time:             testTimestamp,
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
			},
		})

		require.Len(t, aggregator.m, 1)
		// Verify time is populated even though not in field mask.
		for _, value := range aggregator.m {
			assert.Equal(t, testTimestamp, value.ProcessedFlow.Time)
		}
	})
}

func TestAggregatorRunFunction(t *testing.T) {
	t.Run("processes events and resets map", func(t *testing.T) {
		exporter, buf := testExporterWithAggregation(t, 100*time.Millisecond, []string{"verdict"})
		defer exporter.Stop()

		exporter.aggregator.Add(getEventList()[0])

		// Wait for Run cycle to process and reset map.
		assert.Eventually(t, func() bool {
			exporter.aggregator.aggregator.mu.RLock()
			mapSize := len(exporter.aggregator.aggregator.m)
			exporter.aggregator.aggregator.mu.RUnlock()
			return mapSize == 0
		}, timeout, tick)

		assert.NotEmpty(t, buf.String())
	})

	t.Run("handles empty aggregator lifecycle", func(t *testing.T) {
		defer testutils.GoleakVerifyNone(t)

		exporter, buf := testExporterWithAggregation(t, 50*time.Millisecond, []string{"verdict"})

		// Verify aggregator starts and runs without events.
		exporter.aggregator.aggregator.mu.RLock()
		initialMapSize := len(exporter.aggregator.aggregator.m)
		exporter.aggregator.aggregator.mu.RUnlock()
		assert.Equal(t, 0, initialMapSize)

		// Stop aggregator cleanly without any events processed.
		exporter.Stop()

		// Verify no data was written and no goroutines leaked.
		assert.Empty(t, buf.String())
	})

	t.Run("handles encoder errors", func(t *testing.T) {
		buf := &bytesWriteCloser{bytes.Buffer{}}
		opts := testAggregatorOptions(buf)

		// Create a failing encoder that always returns an error.
		opts.newEncoderFunc = func(w io.Writer) (Encoder, error) {
			return &failingEncoder{}, nil
		}

		err := WithAggregationInterval(100 * time.Millisecond)(&opts)
		require.NoError(t, err)
		err = WithFieldAggregate([]string{"verdict"})(&opts)
		require.NoError(t, err)

		exporter, err := newExporter(hivetest.Logger(t), opts)
		require.NoError(t, err)
		defer exporter.Stop()

		exporter.aggregator.Add(getEventList()[0])

		// Wait for aggregation cycle to process and reset map even on encoder error.
		assert.Eventually(t, func() bool {
			exporter.aggregator.aggregator.mu.RLock()
			mapSize := len(exporter.aggregator.aggregator.m)
			exporter.aggregator.aggregator.mu.RUnlock()
			return mapSize == 0
		}, timeout, tick)

		// Buffer should be empty because encoder failed.
		assert.Empty(t, buf.String())
	})
}

func TestAsyncProcessingEdgeCases(t *testing.T) {
	t.Run("aggregator stop after goroutine starts", func(t *testing.T) {
		defer testutils.GoleakVerifyNone(t)

		exporter, _ := testExporterWithAggregation(t, 100*time.Millisecond, []string{"verdict"})

		// Add event to ensure aggregator goroutine is active.
		exporter.aggregator.Add(getEventList()[0])

		// Wait to guarantee the goroutine has started and entered its select loop.
		// We verify this by checking that the event was processed.
		assert.Eventually(t, func() bool {
			exporter.aggregator.aggregator.mu.RLock()
			hasEvents := len(exporter.aggregator.aggregator.m) > 0
			exporter.aggregator.aggregator.mu.RUnlock()
			return hasEvents
		}, timeout, tick)

		// Now stop the exporter, which should cleanly stop the aggregator and cleanup.
		err := exporter.Stop()
		require.NoError(t, err)

		// Goroutine leak verification will ensure proper cleanup.
	})

	t.Run("aggregator stop before goroutine fully starts", func(t *testing.T) {
		defer testutils.GoleakVerifyNone(t)

		exporter, _ := testExporterWithAggregation(t, 100*time.Millisecond, []string{"verdict"})

		// Immediately stop without giving the goroutine time to fully start.
		// This tests the case where stop is called very early.
		err := exporter.Stop()
		require.NoError(t, err)

		// Goroutine leak verification will ensure proper cleanup.
	})

	t.Run("aggregator start called twice", func(t *testing.T) {
		defer testutils.GoleakVerifyNone(t)

		// First Start() is  called during exporter creation.
		exporter, _ := testExporterWithAggregation(t, 100*time.Millisecond, []string{"verdict"})

		// Call Start() again - this should be handled gracefully.
		exporter.aggregator.Start() // This is the SECOND call to Start()

		// Add an event to verify the aggregator still works correctly.
		exporter.aggregator.Add(getEventList()[0])

		// Stop should work normally.
		err := exporter.Stop()
		require.NoError(t, err)
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

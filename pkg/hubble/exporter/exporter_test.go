// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/fake"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	timestamp "google.golang.org/protobuf/types/known/timestamppb"

	aggregatepb "github.com/cilium/cilium/api/v1/aggregate"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

type bytesWriteCloser struct{ bytes.Buffer }

func (bwc *bytesWriteCloser) Close() error { return nil }

type ioWriteCloser struct{ io.Writer }

func (wc *ioWriteCloser) Close() error { return nil }

func TestNewExporterLogOptionsJSON(t *testing.T) {
	// when slog encounters a marshalling error, it stores it in the field with
	// the prefix '!ERROR'. Example:
	//   {..., "options":"!ERROR:json: unsupported type: exporter.NewWriterFunc"}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	_, err := NewExporter(t.Context(), log)
	assert.NoError(t, err)
	assert.NotContains(t, buf.String(), "!ERROR")
}

func TestExporter(t *testing.T) {
	// override node name for unit test.
	nodeName := nodeTypes.GetName()
	newNodeName := "my-node"
	nodeTypes.SetName(newNodeName)
	defer func() {
		nodeTypes.SetName(nodeName)
	}()
	events := []*v1.Event{
		{
			Event: &observerpb.Flow{
				NodeName: newNodeName,
				Time:     &timestamp.Timestamp{Seconds: 1},
			},
		},
		{Timestamp: &timestamp.Timestamp{Seconds: 2}, Event: &observerpb.AgentEvent{}},
		{Timestamp: &timestamp.Timestamp{Seconds: 3}, Event: &observerpb.DebugEvent{}},
		{Timestamp: &timestamp.Timestamp{Seconds: 4}, Event: &observerpb.LostEvent{}},
	}
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	exporter, err := newExporter(t.Context(), log, opts)
	assert.NoError(t, err)

	for _, ev := range events {
		err := exporter.Export(t.Context(), ev)
		assert.NoError(t, err)

	}
	//nolint: testifylint
	assert.Equal(t, `{"flow":{"time":"1970-01-01T00:00:01Z","node_name":"my-node"},"node_name":"my-node","time":"1970-01-01T00:00:01Z"}
{"agent_event":{},"node_name":"my-node","time":"1970-01-01T00:00:02Z"}
{"debug_event":{},"node_name":"my-node","time":"1970-01-01T00:00:03Z"}
{"lost_events":{},"node_name":"my-node","time":"1970-01-01T00:00:04Z"}
`, buf.String())
}

func TestExporterWithFilters(t *testing.T) {
	allowFilterPod := &flowpb.FlowFilter{SourcePod: []string{"namespace-a/"}}
	denyFilterPod := &flowpb.FlowFilter{SourcePod: []string{"namespace-b/"}}
	denyFilterNamespace := &flowpb.FlowFilter{NodeName: []string{"bad/node"}}

	events := []*v1.Event{
		// Non-flow events will not be processed when filters are set
		{Timestamp: &timestamp.Timestamp{Seconds: 2}, Event: &observerpb.AgentEvent{}},
		{Timestamp: &timestamp.Timestamp{Seconds: 3}, Event: &observerpb.DebugEvent{}},
		{Timestamp: &timestamp.Timestamp{Seconds: 4}, Event: &observerpb.LostEvent{}},
		// Does not match allowFilter.
		{
			Event: &observerpb.Flow{
				Time: &timestamp.Timestamp{Seconds: 12},
			},
		},
		// Matches allowFilter.
		{
			Event: &observerpb.Flow{
				Source: &flowpb.Endpoint{Namespace: "namespace-a", PodName: "x"},
				Time:   &timestamp.Timestamp{Seconds: 13},
			},
		},
		// Matches denyFilter.
		{
			Event: &observerpb.Flow{
				Source: &flowpb.Endpoint{Namespace: "namespace-b", PodName: "y"},
				Time:   &timestamp.Timestamp{Seconds: 14},
			},
		},
		// Matches allowFilter, but also denyFilter - not processed.
		{
			Event: &observerpb.Flow{
				Source:   &flowpb.Endpoint{Namespace: "namespace-a", PodName: "v"},
				NodeName: "bad/node",
				Time:     &timestamp.Timestamp{Seconds: 15},
			},
		},
		// Matches allowFilter, but the context gets canceled below before it is processed.
		{
			Event: &observerpb.Flow{
				Source: &flowpb.Endpoint{Namespace: "namespace-a", PodName: "z"},
				Time:   &timestamp.Timestamp{Seconds: 16},
			},
		},
	}
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	for _, opt := range []Option{
		WithAllowList(log, []*flowpb.FlowFilter{allowFilterPod}),
		WithDenyList(log, []*flowpb.FlowFilter{denyFilterPod, denyFilterNamespace}),
	} {
		err := opt(&opts)
		assert.NoError(t, err)
	}

	exporter, err := newExporter(t.Context(), log, opts)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cancelled := false
	for i, ev := range events {
		// Check if processing stops (shouldn't write the last event)
		if i == len(events)-1 {
			cancel()
			cancelled = true
		}
		err := exporter.Export(ctx, ev)
		if cancelled {
			assert.ErrorIs(t, err, context.Canceled)
		} else {
			assert.NoError(t, err)
		}
	}
	assert.JSONEq(t,
		`{"flow":{"time":"1970-01-01T00:00:13Z","source":{"namespace":"namespace-a","pod_name":"x"}},"time":"1970-01-01T00:00:13Z"}
`, buf.String())
}

func TestEventToExportEvent_DefaultCase(t *testing.T) {
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}
	ctx := context.Background()
	exporter, err := newExporter(ctx, log, opts)
	assert.NoError(t, err)

	nilEvent := &v1.Event{
		Timestamp: &timestamp.Timestamp{Seconds: 456},
		Event:     nil,
	}

	result := exporter.eventToExportEvent(nilEvent)
	assert.Nil(t, result)
}

func TestEventToExportEvent(t *testing.T) {
	// override node name for unit test.
	nodeName := nodeTypes.GetName()
	newNodeName := "my-node"
	nodeTypes.SetName(newNodeName)
	defer func() {
		nodeTypes.SetName(nodeName)
	}()

	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	exporter, err := newExporter(t.Context(), log, opts)
	assert.NoError(t, err)

	// flow
	ev := v1.Event{
		Event: &observerpb.Flow{
			NodeName: newNodeName,
			Time:     &timestamp.Timestamp{Seconds: 1},
		},
	}
	res := exporter.eventToExportEvent(&ev)
	expected := &observerpb.ExportEvent{
		ResponseTypes: &observerpb.ExportEvent_Flow{Flow: ev.Event.(*flowpb.Flow)},
		NodeName:      newNodeName,
		Time:          ev.GetFlow().Time,
	}
	assert.Equal(t, expected, res)

	// lost event
	ev = v1.Event{
		Timestamp: &timestamp.Timestamp{Seconds: 1},
		Event:     &observerpb.LostEvent{},
	}
	res = exporter.eventToExportEvent(&ev)
	expected = &observerpb.ExportEvent{
		ResponseTypes: &observerpb.ExportEvent_LostEvents{LostEvents: ev.Event.(*flowpb.LostEvent)},
		NodeName:      newNodeName,
		Time:          ev.Timestamp,
	}
	assert.Equal(t, expected, res)

	// agent event
	ev = v1.Event{
		Timestamp: &timestamp.Timestamp{Seconds: 1},
		Event:     &observerpb.AgentEvent{},
	}
	res = exporter.eventToExportEvent(&ev)
	expected = &observerpb.ExportEvent{
		ResponseTypes: &observerpb.ExportEvent_AgentEvent{AgentEvent: ev.Event.(*flowpb.AgentEvent)},
		NodeName:      newNodeName,
		Time:          ev.Timestamp,
	}
	assert.Equal(t, expected, res)

	// debug event
	ev = v1.Event{
		Timestamp: &timestamp.Timestamp{Seconds: 1},
		Event:     &observerpb.DebugEvent{},
	}
	res = exporter.eventToExportEvent(&ev)
	expected = &observerpb.ExportEvent{
		ResponseTypes: &observerpb.ExportEvent_DebugEvent{DebugEvent: ev.Event.(*flowpb.DebugEvent)},
		NodeName:      newNodeName,
		Time:          ev.Timestamp,
	}
	assert.Equal(t, expected, res)
}

func TestExporterWithFieldMask(t *testing.T) {
	events := []*v1.Event{
		{
			Event: &observerpb.Flow{
				NodeName: "nodeName",
				Time:     &timestamp.Timestamp{Seconds: 12},
				Source:   &flowpb.Endpoint{PodName: "podA", Namespace: "nsA"},
			},
		},
		{
			Event: &observerpb.Flow{
				NodeName:    "nodeName",
				Time:        &timestamp.Timestamp{Seconds: 13},
				Destination: &flowpb.Endpoint{PodName: "podB", Namespace: "nsB"}},
		},
	}
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}
	for _, opt := range []Option{
		WithFieldMask([]string{"source"}),
	} {
		err := opt(&opts)
		assert.NoError(t, err)
	}

	exporter, err := newExporter(t.Context(), log, opts)
	assert.NoError(t, err)

	for _, ev := range events {
		err := exporter.Export(t.Context(), ev)
		assert.NoError(t, err)
	}

	// nolint: testifylint
	assert.Equal(t, `{"flow":{"source":{"namespace":"nsA","pod_name":"podA"}}}
{"flow":{}}
`, buf.String())
}

type boolOnExportEvent bool

func (e *boolOnExportEvent) OnExportEvent(ctx context.Context, ev *v1.Event, encoder Encoder) (stop bool, err error) {
	*e = true
	return false, nil
}

func TestExporterOnExportEvent(t *testing.T) {
	// override node name for unit test.
	nodeName := nodeTypes.GetName()
	newNodeName := "my-node"
	nodeTypes.SetName(newNodeName)
	defer func() {
		nodeTypes.SetName(nodeName)
	}()

	events := []*v1.Event{
		{
			Event: &observerpb.Flow{
				NodeName: newNodeName,
				Time:     &timestamp.Timestamp{Seconds: 1},
			},
		},
		{Timestamp: &timestamp.Timestamp{Seconds: 2}, Event: &observerpb.DebugEvent{}},
	}

	var hookStruct boolOnExportEvent
	var hookNoOpFuncCalled bool
	var hookNoOpFuncCalledAfterAbort bool

	var agentEventExported bool
	var abortRequested bool

	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}
	for _, opt := range []Option{
		WithOnExportEvent(&hookStruct),
		WithOnExportEventFunc(func(ctx context.Context, ev *v1.Event, encoder Encoder) (stop bool, err error) {
			hookNoOpFuncCalled = true
			return false, nil
		}),
		WithOnExportEventFunc(func(ctx context.Context, ev *v1.Event, encoder Encoder) (stop bool, err error) {
			if agentEventExported {
				abortRequested = true
				return true, nil
			}
			agentEventExported = true
			agentEvent := &v1.Event{Timestamp: &timestamp.Timestamp{Seconds: 3}, Event: &observerpb.AgentEvent{}}
			return false, encoder.Encode(agentEvent)
		}),
		WithOnExportEventFunc(func(ctx context.Context, ev *v1.Event, encoder Encoder) (stop bool, err error) {
			if abortRequested {
				// not reachable
				hookNoOpFuncCalledAfterAbort = true
			}
			return false, nil
		}),
	} {
		err := opt(&opts)
		assert.NoError(t, err)
	}

	exporter, err := newExporter(t.Context(), log, opts)
	assert.NoError(t, err)

	ctx := t.Context()
	for _, ev := range events {
		err := exporter.Export(ctx, ev)
		assert.NoError(t, err)
	}

	assert.Truef(t, bool(hookStruct), "hook struct not called")
	assert.Truef(t, hookNoOpFuncCalled, "hook no-op func not called")
	assert.Falsef(t, hookNoOpFuncCalledAfterAbort, "hook no-op func was called after abort requested by previous hook")

	// ensure that aborting OnExportEvent hook processing works (debug_event should not be exported)
	// nolint: testifylint
	assert.Equal(t, `{"Timestamp":{"seconds":3},"Event":{}}
{"flow":{"time":"1970-01-01T00:00:01Z","node_name":"my-node"},"node_name":"my-node","time":"1970-01-01T00:00:01Z"}
`, buf.String())
}

func TestExporterWithFieldAggregate(t *testing.T) {
	opts := DefaultOptions

	// Test WithFieldAggregate with valid fields
	err := WithFieldAggregate([]string{"source.identity", "destination.pod_name"})(&opts)
	assert.NoError(t, err)
	assert.NotNil(t, opts.FieldAggregate)

	// Test WithFieldAggregate with invalid fields
	err = WithFieldAggregate([]string{"invalid-field"})(&opts)
	assert.Error(t, err)
}

func TestExporterWithAggregationInterval(t *testing.T) {
	opts := DefaultOptions

	// Test WithAggregationInterval with valid duration
	testInterval := 60 * time.Second
	err := WithAggregationInterval(testInterval)(&opts)
	assert.NoError(t, err)
	assert.Equal(t, testInterval, opts.aggregationInterval)

	// Test with zero duration
	err = WithAggregationInterval(0)(&opts)
	assert.NoError(t, err)
	assert.Equal(t, time.Duration(0), opts.aggregationInterval)
}

func TestOptionsGetters(t *testing.T) {
	opts := DefaultOptions

	// Test FieldAggregate getter
	testFields := []string{"source.identity", "destination.pod_name"}
	err := WithFieldAggregate(testFields)(&opts)
	assert.NoError(t, err)
	retrievedFieldAggregate := opts.FieldAggregate
	assert.NotNil(t, retrievedFieldAggregate)

	// Test AggregationInterval getter
	testInterval := 45 * time.Second
	err = WithAggregationInterval(testInterval)(&opts)
	assert.NoError(t, err)
	retrievedInterval := opts.aggregationInterval
	assert.Equal(t, testInterval, retrievedInterval)
}

func TestExporterWithNewWriterFunc(t *testing.T) {
	opts := DefaultOptions

	// Test WithNewWriterFunc with custom writer
	customWriterCalled := false
	customWriter := func() (io.WriteCloser, error) {
		customWriterCalled = true
		return &bytesWriteCloser{bytes.Buffer{}}, nil
	}

	err := WithNewWriterFunc(customWriter)(&opts)
	assert.NoError(t, err)

	// Verify the writer function was set
	writer, err := opts.NewWriterFunc()()
	assert.NoError(t, err)
	assert.NotNil(t, writer)
	assert.True(t, customWriterCalled)
	writer.Close()
}

func TestExporterWithNewEncoderFunc(t *testing.T) {
	opts := DefaultOptions

	// Test WithNewEncoderFunc with custom encoder
	customEncoderCalled := false
	customEncoder := func(w io.Writer) (Encoder, error) {
		customEncoderCalled = true
		return JsonEncoder(w)
	}

	err := WithNewEncoderFunc(customEncoder)(&opts)
	assert.NoError(t, err)

	// Verify the encoder function was set
	var buf bytes.Buffer
	encoder, err := opts.NewEncoderFunc()(&buf)
	assert.NoError(t, err)
	assert.NotNil(t, encoder)
	assert.True(t, customEncoderCalled)
}

func TestExporterAggregatorConfiguration(t *testing.T) {
	// Test that aggregator is not initialized when field aggregation is not active
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	exporter, err := newExporter(context.Background(), log, opts)
	assert.NoError(t, err)
	assert.Nil(t, exporter.aggregator)
	assert.False(t, exporter.opts.FieldAggregate.Active())

	fieldAggregateIntervalOption := WithAggregationInterval(100 * time.Millisecond)
	err = fieldAggregateIntervalOption(&opts)
	assert.NoError(t, err)

	fieldAggregateOption := WithFieldAggregate([]string{"source.namespace", "destination.namespace", "verdict"})
	err = fieldAggregateOption(&opts)
	assert.NoError(t, err)

	exporterWithAggregation, err := newExporter(context.Background(), log, opts)
	assert.NoError(t, err)
	assert.NotNil(t, exporterWithAggregation.aggregator)
	assert.True(t, exporterWithAggregation.opts.FieldAggregate.Active())

	// Clean up
	err = exporterWithAggregation.Stop()
	assert.NoError(t, err)
	err = exporter.Stop()
	assert.NoError(t, err)
}

func TestExporterAggregationDisabledWhenIntervalZero(t *testing.T) {
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	// Configure field aggregation fields but interval=0
	fieldAggregateOption := WithFieldAggregate([]string{"verdict"})
	err := fieldAggregateOption(&opts)
	assert.NoError(t, err)
	// Explicitly override default (30s) to zero to disable aggregation
	zeroInterval := WithAggregationInterval(0)
	err = zeroInterval(&opts)
	assert.NoError(t, err)

	exporter, err := newExporter(context.Background(), log, opts)
	assert.NoError(t, err)
	defer exporter.Stop()

	assert.Nil(t, exporter.aggregator, "aggregator should be disabled when interval <= 0")

	// Send two flow events that would otherwise aggregate
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		err := exporter.Export(ctx, &v1.Event{Event: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}})
		assert.NoError(t, err)
	}

	// Expect two separate JSON lines (raw export) because aggregation is disabled
	output := buf.String()
	lineCount := 0
	for _, ln := range bytes.Split([]byte(output), []byte("\n")) {
		if len(ln) > 0 {
			lineCount++
		}
	}
	assert.Equal(t, 2, lineCount, "expected two raw exported flow lines, got output: %s", output)
}

func TestExporterWithFieldAggregate2(t *testing.T) {
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	err := WithAggregationInterval(100 * time.Millisecond)(&opts)
	assert.NoError(t, err)

	err = WithFieldAggregate([]string{"verdict"})(&opts)
	assert.NoError(t, err)

	ctx := context.Background()
	exporter, err := newExporter(ctx, log, opts)
	assert.NoError(t, err)
	defer exporter.Stop()

	// Test that flow events are added to aggregator
	event := &v1.Event{Event: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED}}
	err = exporter.Export(ctx, event)
	assert.NoError(t, err)
	event = &v1.Event{Event: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}}
	err = exporter.Export(ctx, event)
	assert.NoError(t, err)
	// Wait for async processing to complete
	time.Sleep(10 * time.Millisecond)
	assert.Len(t, exporter.aggregator.aggregator.m, 2)

	// Test that non-flow events bypass aggregation
	nonFlowEvent := &v1.Event{Timestamp: &timestamp.Timestamp{Seconds: 100}, Event: &observerpb.AgentEvent{}}
	err = exporter.Export(ctx, nonFlowEvent)
	assert.NoError(t, err)
	time.Sleep(5 * time.Millisecond)
	assert.Len(t, exporter.aggregator.aggregator.m, 2) // No change in aggregator
}

func TestProcessedFlowToAggregatedExportEvent(t *testing.T) {
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	err := WithAggregationInterval(100 * time.Millisecond)(&opts)
	assert.NoError(t, err)

	err = WithFieldAggregate([]string{"verdict", "source.pod_name"})(&opts)
	assert.NoError(t, err)

	ctx := context.Background()
	exporter, err := newExporter(ctx, log, opts)
	assert.NoError(t, err)
	defer exporter.Stop()

	// Create a pre-processed flow
	processedFlow := &flowpb.Flow{
		Verdict: flowpb.Verdict_FORWARDED,
		Source: &flowpb.Endpoint{
			PodName: "test-pod", // Only pod_name should be present as defined in FieldAggregate

		},
	}

	ingressCount, egressCount, unknownDirectionCount := 5, 3, 1

	result := processedFlowToAggregatedExportEvent(processedFlow, ingressCount, egressCount, unknownDirectionCount)
	assert.NotNil(t, result)

	flow := result.GetFlow()
	assert.NotNil(t, flow)

	aggregate, err := extractAggregateFromExtensions(flow)
	assert.NoError(t, err)
	assert.NotNil(t, aggregate)
	assert.Equal(t, uint32(ingressCount), aggregate.IngressFlowCount)
	assert.Equal(t, uint32(egressCount), aggregate.EgressFlowCount)
	assert.Equal(t, uint32(unknownDirectionCount), aggregate.UnknownDirectionFlowCount)

	assert.Equal(t, processedFlow.Verdict, flow.Verdict)
	assert.Equal(t, "test-pod", flow.Source.PodName)
	assert.Nil(t, flow.Destination) // Should not have any fields not defined in FieldAggregate
	assert.Empty(t, flow.GetNodeName())
	assert.Nil(t, flow.GetTime())
}

// helper func to extract Aggregate from flow.Extensions field
func extractAggregateFromExtensions(flow *flowpb.Flow) (*aggregatepb.Aggregate, error) {
	if flow.Extensions == nil {
		return nil, nil
	}

	aggregate := &aggregatepb.Aggregate{}
	if err := flow.Extensions.UnmarshalTo(aggregate); err != nil {
		return nil, err
	}

	return aggregate, nil
}

func BenchmarkExporter(b *testing.B) {
	allowNS, denyNS := fake.K8sNamespace(), fake.K8sNamespace()
	for allowNS == denyNS {
		allowNS, denyNS = fake.K8sNamespace(), fake.K8sNamespace()
	}
	allowEvent := v1.Event{
		Event: &observerpb.Flow{
			Time:     &timestamp.Timestamp{Seconds: 1},
			NodeName: fake.K8sNodeName(),
			Source: &flowpb.Endpoint{
				Namespace: allowNS,
				PodName:   fake.K8sPodName(),
				Labels:    fake.K8sLabels(),
			},
			Destination: &flowpb.Endpoint{
				Namespace: allowNS,
				PodName:   fake.K8sPodName(),
				Labels:    fake.K8sLabels(),
			},
			SourceNames:      fake.Names(2),
			DestinationNames: fake.Names(2),
			Verdict:          flowpb.Verdict_AUDIT,
			Summary:          fake.AlphaNum(20),
		},
	}
	noAllowEvent := v1.Event{
		Event: &observerpb.Flow{
			Time:     &timestamp.Timestamp{Seconds: 1},
			NodeName: fake.K8sNodeName(),
			Source: &flowpb.Endpoint{
				Namespace: denyNS,
				PodName:   fake.K8sPodName(),
				Labels:    fake.K8sLabels(),
			},
			Destination: &flowpb.Endpoint{
				Namespace: allowNS,
				PodName:   fake.K8sPodName(),
				Labels:    fake.K8sLabels(),
			},
			SourceNames:      fake.Names(2),
			DestinationNames: fake.Names(2),
			Verdict:          flowpb.Verdict_AUDIT,
			Summary:          fake.AlphaNum(20),
		},
	}
	denyEvent := v1.Event{
		Event: &observerpb.Flow{
			Time:     &timestamp.Timestamp{Seconds: 1},
			NodeName: fake.K8sNodeName(),
			Source: &flowpb.Endpoint{
				Namespace: allowNS,
				PodName:   fake.K8sPodName(),
				Labels:    fake.K8sLabels(),
			},
			Destination: &flowpb.Endpoint{
				Namespace: denyNS,
				PodName:   fake.K8sPodName(),
				Labels:    fake.K8sLabels(),
			},
			SourceNames:      fake.Names(2),
			DestinationNames: fake.Names(2),
			Verdict:          flowpb.Verdict_AUDIT,
			Summary:          fake.AlphaNum(20),
		},
	}

	buf := &ioWriteCloser{io.Discard}
	log := hivetest.Logger(b)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}
	for _, opt := range []Option{
		WithFieldMask([]string{"time", "node_name", "source"}),
		WithAllowList(log, []*flowpb.FlowFilter{
			{SourcePod: []string{"no-matches-for-this-one"}},
			{SourcePod: []string{allowNS + "/"}},
		}),
		WithDenyList(log, []*flowpb.FlowFilter{
			{DestinationPod: []string{"no-matches-for-this-one"}},
			{DestinationPod: []string{denyNS + "/"}},
		}),
	} {
		err := opt(&opts)
		assert.NoError(b, err)
	}

	exporter, err := newExporter(b.Context(), log, opts)
	assert.NoError(b, err)

	ctx := b.Context()

	for i := 0; b.Loop(); i++ {
		event := &allowEvent
		if i%10 == 0 { // 10% doesn't match allow filter
			event = &noAllowEvent
		}
		if i%10 == 1 { // 10% matches deny filter
			event = &denyEvent
		}
		err := exporter.Export(ctx, event)
		assert.NoError(b, err)
	}
}

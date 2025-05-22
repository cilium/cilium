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

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
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
	_, err := NewExporter(log)
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

	exporter, err := newExporter(log, opts)
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

	exporter, err := newExporter(log, opts)
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

	exporter, err := newExporter(log, opts)
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

	exporter, err := newExporter(log, opts)
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

	exporter, err := newExporter(log, opts)
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

	exporter, err := newExporter(log, opts)
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

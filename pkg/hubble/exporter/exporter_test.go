// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/cilium/fake"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	timestamp "google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type bytesWriteCloser struct{ bytes.Buffer }

func (bwc *bytesWriteCloser) Close() error { return nil }

type ioWriteCloser struct{ io.Writer }

func (wc *ioWriteCloser) Close() error { return nil }

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
	log := logrus.New()
	log.SetOutput(io.Discard)
	exporter, err := newExporter(context.Background(), log, buf, exporteroption.Default)
	assert.NoError(t, err)

	ctx := context.Background()
	for _, ev := range events {
		stop, err := exporter.OnDecodedEvent(ctx, ev)
		assert.False(t, stop)
		assert.NoError(t, err)

	}
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
	log := logrus.New()
	log.SetOutput(io.Discard)

	opts := exporteroption.Default
	for _, opt := range []exporteroption.Option{
		exporteroption.WithAllowList(log, []*flowpb.FlowFilter{allowFilterPod}),
		exporteroption.WithDenyList(log, []*flowpb.FlowFilter{denyFilterPod, denyFilterNamespace}),
	} {
		err := opt(&opts)
		assert.NoError(t, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exporter, err := newExporter(ctx, log, buf, opts)
	assert.NoError(t, err)

	for i, ev := range events {
		// Check if processing stops (shouldn't write the last event)
		if i == len(events)-1 {
			cancel()
		}
		stop, err := exporter.OnDecodedEvent(ctx, ev)
		assert.False(t, stop)
		assert.NoError(t, err)

	}
	assert.Equal(t,
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
	log := logrus.New()
	log.SetOutput(io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exporter, err := newExporter(ctx, log, buf, exporteroption.Default)
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
	log := logrus.New()
	log.SetOutput(io.Discard)

	opts := exporteroption.Default
	for _, opt := range []exporteroption.Option{
		exporteroption.WithFieldMask([]string{"source"}),
	} {
		err := opt(&opts)
		assert.NoError(t, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exporter, err := newExporter(ctx, log, buf, opts)
	assert.NoError(t, err)

	for _, ev := range events {
		stop, err := exporter.OnDecodedEvent(ctx, ev)
		assert.False(t, stop)
		assert.NoError(t, err)
	}

	assert.Equal(t, `{"flow":{"source":{"namespace":"nsA","pod_name":"podA"}}}
{"flow":{}}
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
	log := logrus.New()
	log.SetOutput(io.Discard)

	opts := exporteroption.Default
	for _, opt := range []exporteroption.Option{
		exporteroption.WithFieldMask([]string{"time", "node_name", "source"}),
		exporteroption.WithAllowList(log, []*flowpb.FlowFilter{
			{SourcePod: []string{"no-matches-for-this-one"}},
			{SourcePod: []string{allowNS + "/"}},
		}),
		exporteroption.WithDenyList(log, []*flowpb.FlowFilter{
			{DestinationPod: []string{"no-matches-for-this-one"}},
			{DestinationPod: []string{denyNS + "/"}},
		}),
	} {
		err := opt(&opts)
		assert.NoError(b, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exporter, err := newExporter(ctx, log, buf, opts)
	assert.NoError(b, err)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		event := &allowEvent
		if i%10 == 0 { // 10% doesn't match allow filter
			event = &noAllowEvent
		}
		if i%10 == 1 { // 10% matches deny filter
			event = &denyEvent
		}
		stop, err := exporter.OnDecodedEvent(ctx, event)
		assert.False(b, stop)
		assert.NoError(b, err)
	}
}

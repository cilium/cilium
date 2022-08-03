// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

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
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	log := logrus.New()
	log.SetOutput(io.Discard)
	exporter := newExporter(log, encoder)
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

func TestEventToExportEvent(t *testing.T) {
	// override node name for unit test.
	nodeName := nodeTypes.GetName()
	newNodeName := "my-node"
	nodeTypes.SetName(newNodeName)
	defer func() {
		nodeTypes.SetName(nodeName)
	}()

	// flow
	ev := v1.Event{
		Event: &observerpb.Flow{
			NodeName: newNodeName,
			Time:     &timestamp.Timestamp{Seconds: 1},
		},
	}
	res := eventToExportEvent(&ev)
	expected := &observerpb.ExportEvent{
		ResponseTypes: &observerpb.ExportEvent_Flow{Flow: ev.Event.(*flowpb.Flow)},
		NodeName:      newNodeName,
		Time:          ev.GetFlow().Time,
	}
	assert.Equal(t, res, expected)

	// lost event
	ev = v1.Event{
		Timestamp: &timestamp.Timestamp{Seconds: 1},
		Event:     &observerpb.LostEvent{},
	}
	res = eventToExportEvent(&ev)
	expected = &observerpb.ExportEvent{
		ResponseTypes: &observerpb.ExportEvent_LostEvents{LostEvents: ev.Event.(*flowpb.LostEvent)},
		NodeName:      newNodeName,
		Time:          ev.Timestamp,
	}
	assert.Equal(t, res, expected)

	// agent event
	ev = v1.Event{
		Timestamp: &timestamp.Timestamp{Seconds: 1},
		Event:     &observerpb.AgentEvent{},
	}
	res = eventToExportEvent(&ev)
	expected = &observerpb.ExportEvent{
		ResponseTypes: &observerpb.ExportEvent_AgentEvent{AgentEvent: ev.Event.(*flowpb.AgentEvent)},
		NodeName:      newNodeName,
		Time:          ev.Timestamp,
	}
	assert.Equal(t, res, expected)

	// debug event
	ev = v1.Event{
		Timestamp: &timestamp.Timestamp{Seconds: 1},
		Event:     &observerpb.DebugEvent{},
	}
	res = eventToExportEvent(&ev)
	expected = &observerpb.ExportEvent{
		ResponseTypes: &observerpb.ExportEvent_DebugEvent{DebugEvent: ev.Event.(*flowpb.DebugEvent)},
		NodeName:      newNodeName,
		Time:          ev.Timestamp,
	}
	assert.Equal(t, res, expected)
}

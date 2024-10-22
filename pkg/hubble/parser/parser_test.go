// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package parser

import (
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(io.Discard)
}

func Test_InvalidPayloads(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	_, err = p.Decode(nil)
	assert.Equal(t, err, errors.ErrEmptyData)

	_, err = p.Decode(&observerTypes.MonitorEvent{
		Payload: nil,
	})
	assert.Equal(t, err, errors.ErrEmptyData)

	_, err = p.Decode(&observerTypes.MonitorEvent{
		Payload: &observerTypes.PerfEvent{
			Data: []byte{100},
		},
	})
	assert.Equal(t, err, errors.NewErrInvalidType(100))

	_, err = p.Decode(&observerTypes.MonitorEvent{
		Payload: "not valid",
	})
	assert.Equal(t, err, errors.ErrUnknownEventType)
}

func Test_ParserDispatch(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	// Test L3/L4 record
	tn := monitor.TraceNotifyV0{
		Type: byte(api.MessageTypeTrace),
	}
	data, err := testutils.CreateL3L4Payload(tn)
	assert.NoError(t, err)

	id := uuid.New()
	e, err := p.Decode(&observerTypes.MonitorEvent{
		UUID: id,
		Payload: &observerTypes.PerfEvent{
			Data: data,
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, flowpb.FlowType_L3_L4, e.GetFlow().GetType())
	assert.Equal(t, id.String(), e.GetFlow().GetUuid())

	// Test L7 dispatch
	node := "k8s1"
	e, err = p.Decode(&observerTypes.MonitorEvent{
		UUID:     id,
		NodeName: node,
		Payload: &observerTypes.AgentEvent{
			Type: api.MessageTypeAccessLog,
			Message: accesslog.LogRecord{
				Timestamp: "2006-01-02T15:04:05.999999999Z",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, node, e.GetFlow().GetNodeName())
	assert.Equal(t, flowpb.FlowType_L7, e.GetFlow().GetType())
	assert.Equal(t, id.String(), e.GetFlow().GetUuid())
}

func Test_EventType_RecordLost(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	ts := time.Now()
	ev, err := p.Decode(&observerTypes.MonitorEvent{
		Timestamp: ts,
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourcePerfRingBuffer,
			NumLostEvents: 1001,
			CPU:           3,
		},
	})
	assert.NoError(t, err)

	protoTimestamp := timestamppb.New(ts)
	assert.NoError(t, protoTimestamp.CheckValid())
	assert.Equal(t, &v1.Event{
		Timestamp: protoTimestamp,
		Event: &flowpb.LostEvent{
			NumEventsLost: 1001,
			Cpu:           &wrapperspb.Int32Value{Value: 3},
			Source:        flowpb.LostEventSource_PERF_EVENT_RING_BUFFER,
		},
	}, ev)
}

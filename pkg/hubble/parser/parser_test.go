// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package parser

import (
	"io"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(io.Discard)
}

func Test_InvalidPayloads(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil)
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
	p, err := New(log, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	// Test L3/L4 record
	tn := monitor.TraceNotifyV0{
		Type: byte(api.MessageTypeTrace),
	}
	data, err := testutils.CreateL3L4Payload(tn)
	assert.NoError(t, err)

	e, err := p.Decode(&observerTypes.MonitorEvent{
		Payload: &observerTypes.PerfEvent{
			Data: data,
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, flowpb.FlowType_L3_L4, e.GetFlow().GetType())

	// Test L7 dispatch
	node := "k8s1"
	e, err = p.Decode(&observerTypes.MonitorEvent{
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
}

func Test_EventType_RecordLost(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil)
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

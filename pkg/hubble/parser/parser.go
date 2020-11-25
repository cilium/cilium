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

package parser

import (
	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/agent"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/hubble/parser/seven"
	"github.com/cilium/cilium/pkg/hubble/parser/threefour"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
)

// Parser for all flows
type Parser struct {
	l34 *threefour.Parser
	l7  *seven.Parser
}

// New creates a new parser
func New(
	log logrus.FieldLogger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	opts ...options.Option,
) (*Parser, error) {

	l34, err := threefour.New(log, endpointGetter, identityGetter, dnsGetter, ipGetter, serviceGetter)
	if err != nil {
		return nil, err
	}

	l7, err := seven.New(log, dnsGetter, ipGetter, serviceGetter, opts...)
	if err != nil {
		return nil, err
	}

	return &Parser{
		l34: l34,
		l7:  l7,
	}, nil
}

func lostEventSourceToProto(source int) pb.LostEventSource {
	switch source {
	case observerTypes.LostEventSourcePerfRingBuffer:
		return pb.LostEventSource_PERF_EVENT_RING_BUFFER
	case observerTypes.LostEventSourceEventsQueue:
		return pb.LostEventSource_OBSERVER_EVENTS_QUEUE
	default:
		return pb.LostEventSource_UNKNOWN_LOST_EVENT_SOURCE
	}
}

// Decode decodes a cilium monitor 'payload' and returns a v1.Event with
// the Event field populated.
func (p *Parser) Decode(monitorEvent *observerTypes.MonitorEvent) (*v1.Event, error) {
	if monitorEvent == nil {
		return nil, errors.ErrEmptyData
	}

	// TODO: Pool decoded flows instead of allocating new objects each time.
	ts, _ := ptypes.TimestampProto(monitorEvent.Timestamp)
	ev := &v1.Event{
		Timestamp: ts,
	}

	switch payload := monitorEvent.Payload.(type) {
	case *observerTypes.PerfEvent:
		flow := &pb.Flow{}
		if err := p.l34.Decode(payload.Data, flow); err != nil {
			return nil, err
		}
		// FIXME: Time and NodeName are now part of GetFlowsResponse. We
		// populate these fields for compatibility with old clients.
		flow.Time = ts
		flow.NodeName = monitorEvent.NodeName
		ev.Event = flow
		return ev, nil
	case *observerTypes.AgentEvent:
		switch payload.Type {
		case monitorAPI.MessageTypeAccessLog:
			flow := &pb.Flow{}
			logrecord, ok := payload.Message.(accesslog.LogRecord)
			if !ok {
				return nil, errors.ErrInvalidAgentMessageType
			}
			if err := p.l7.Decode(&logrecord, flow); err != nil {
				return nil, err
			}
			// FIXME: Time and NodeName are now part of GetFlowsResponse. We
			// populate these fields for compatibility with old clients.
			flow.Time = ts
			flow.NodeName = monitorEvent.NodeName
			ev.Event = flow
			return ev, nil
		case monitorAPI.MessageTypeAgent:
			agentNotifyMessage, ok := payload.Message.(monitorAPI.AgentNotifyMessage)
			if !ok {
				return nil, errors.ErrInvalidAgentMessageType
			}
			ev.Event = agent.NotifyMessageToProto(agentNotifyMessage)
			return ev, nil
		default:
			return nil, errors.ErrUnknownEventType
		}
	case *observerTypes.LostEvent:
		ev.Event = &pb.LostEvent{
			Source:        lostEventSourceToProto(payload.Source),
			NumEventsLost: payload.NumLostEvents,
			Cpu: &wrappers.Int32Value{
				Value: int32(payload.CPU),
			},
		}
		return ev, nil
	case nil:
		return ev, errors.ErrEmptyData
	default:
		return nil, errors.ErrUnknownEventType
	}
}

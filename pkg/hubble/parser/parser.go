// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Copyright Authors of Cilium

package parser

import (
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/agent"
	"github.com/cilium/cilium/pkg/hubble/parser/debug"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/hubble/parser/seven"
	"github.com/cilium/cilium/pkg/hubble/parser/sock"
	"github.com/cilium/cilium/pkg/hubble/parser/threefour"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// Parser for all flows
type Parser struct {
	l34  *threefour.Parser
	l7   *seven.Parser
	dbg  *debug.Parser
	sock *sock.Parser
}

// New creates a new parser
func New(
	log logrus.FieldLogger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	linkGetter getters.LinkGetter,
	cgroupGetter getters.PodMetadataGetter,
	opts ...options.Option,
) (*Parser, error) {

	l34, err := threefour.New(log, endpointGetter, identityGetter, dnsGetter, ipGetter, serviceGetter, linkGetter)
	if err != nil {
		return nil, err
	}

	l7, err := seven.New(log, dnsGetter, ipGetter, serviceGetter, endpointGetter, opts...)
	if err != nil {
		return nil, err
	}

	dbg, err := debug.New(log, endpointGetter)
	if err != nil {
		return nil, err
	}

	sock, err := sock.New(log, endpointGetter, identityGetter, dnsGetter, ipGetter, serviceGetter, cgroupGetter)
	if err != nil {
		return nil, err
	}

	return &Parser{
		l34:  l34,
		l7:   l7,
		dbg:  dbg,
		sock: sock,
	}, nil
}

func lostEventSourceToProto(source int) pb.LostEventSource {
	switch source {
	case observerTypes.LostEventSourcePerfRingBuffer:
		return pb.LostEventSource_PERF_EVENT_RING_BUFFER
	case observerTypes.LostEventSourceEventsQueue:
		return pb.LostEventSource_OBSERVER_EVENTS_QUEUE
	case observerTypes.LostEventSourceHubbleRingBuffer:
		return pb.LostEventSource_HUBBLE_RING_BUFFER
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
	ts := timestamppb.New(monitorEvent.Timestamp)
	ev := &v1.Event{
		Timestamp: ts,
	}

	switch payload := monitorEvent.Payload.(type) {
	case *observerTypes.PerfEvent:
		if len(payload.Data) == 0 {
			return nil, errors.ErrEmptyData
		}

		flow := &pb.Flow{}
		switch payload.Data[0] {
		case monitorAPI.MessageTypeDebug:
			// Debug and TraceSock are both perf ring buffer events without any
			// associated captured network packet header, so we treat them
			// separately
			dbg, err := p.dbg.Decode(payload.Data, payload.CPU)
			if err != nil {
				return nil, err
			}
			ev.Event = dbg
			return ev, nil
		case monitorAPI.MessageTypeTraceSock:
			if err := p.sock.Decode(payload.Data, flow); err != nil {
				return nil, err
			}
		default:
			if err := p.l34.Decode(payload.Data, flow); err != nil {
				return nil, err
			}
		}
		flow.Uuid = monitorEvent.UUID.String()
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
			flow.Uuid = monitorEvent.UUID.String()
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
			Cpu: &wrapperspb.Int32Value{
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

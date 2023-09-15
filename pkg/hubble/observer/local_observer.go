// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/build"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	parserErrors "github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// DefaultOptions to include in the server. Other packages may extend this
// in their init() function.
var DefaultOptions []observeroption.Option

// LocalObserverServer is an implementation of the server.Observer interface
// that's meant to be run embedded inside the Cilium process. It ignores all
// the state change events since the state is available locally.
type LocalObserverServer struct {
	// event buffer that contains the references of all flows
	eventBuffer container.EventReadWriter

	// events is the channel used by the writer(s) to send the flow data
	// into the observer server.
	events chan *observerTypes.MonitorEvent

	// stopped is mostly used in unit tests to signalize when the events
	// channel is empty, once it's closed.
	stopped chan struct{}

	log logrus.FieldLogger

	// payloadParser decodes flowpb.Payload into flowpb.Flow
	payloadParser *parser.Parser

	opts observeroption.Options

	// startTime is the time when this instance was started
	startTime time.Time

	// numObservedFlows counts how many flows have been observed
	numObservedFlows atomic.Uint64

	namespaceManager NamespaceManager
}

// NewLocalServer returns a new local observer server.
func NewLocalServer(
	payloadParser *parser.Parser,
	namespaceManager NamespaceManager,
	logger logrus.FieldLogger,
	options ...observeroption.Option,
) (*LocalObserverServer, error) {
	opts := observeroption.Default // start with defaults
	options = append(options, DefaultOptions...)
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}

	logger.WithFields(logrus.Fields{
		"eventQueueSize": opts.MonitorBuffer,
	}).Info("Configuring Hubble server")

	const (
		flowStorageRingBuffer = iota
		flowStorageBadgerDBDisk
		flowStorageBadgerDBInMemory
		flowStorageStateDB
	)

	flowStorage := flowStorageBadgerDBDisk

	var eventBuffer container.EventReadWriter
	switch flowStorage {
	case flowStorageBadgerDBDisk, flowStorageBadgerDBInMemory:
		inMemory := flowStorage == flowStorageBadgerDBInMemory
		eventTTL := 5 * time.Minute
		var err error
		eventBuffer, err = container.NewBadgerDB(inMemory, eventTTL)
		if err != nil {
			logger.WithError(err).Error("failed in NewEventBuffer")
			return nil, err
		}
	case flowStorageRingBuffer:
		eventBuffer = container.NewRing(opts.MaxFlows)
	case flowStorageStateDB:
		panic("not implemented")
	}

	s := &LocalObserverServer{
		log:              logger,
		eventBuffer:      eventBuffer,
		events:           make(chan *observerTypes.MonitorEvent, opts.MonitorBuffer),
		stopped:          make(chan struct{}),
		payloadParser:    payloadParser,
		startTime:        time.Now(),
		namespaceManager: namespaceManager,
		opts:             opts,
	}

	for _, f := range s.opts.OnServerInit {
		err := f.OnServerInit(s)
		if err != nil {
			s.log.WithError(err).Error("failed in OnServerInit")
			return nil, err
		}
	}

	return s, nil
}

// Start implements GRPCServer.Start.
func (s *LocalObserverServer) Start() {
	// We use a cancellation context here so that any goroutines spawned in the
	// OnMonitorEvent/OnDecodedFlow/OnDecodedEvent hooks have a signal for cancellation.
	// When Start() returns, the deferred cancel() will run and we expect hooks
	// to stop any goroutines that may have spawned by listening to the
	// ctx.Done() channel for the stop signal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

nextEvent:
	for monitorEvent := range s.GetEventsChannel() {
		for _, f := range s.opts.OnMonitorEvent {
			stop, err := f.OnMonitorEvent(ctx, monitorEvent)
			if err != nil {
				s.log.WithError(err).WithField("event", monitorEvent).Info("failed in OnMonitorEvent")
			}
			if stop {
				continue nextEvent
			}
		}

		ev, err := s.payloadParser.Decode(monitorEvent)
		if err != nil {
			switch {
			case
				// silently ignore unknown or skipped events
				errors.Is(err, parserErrors.ErrUnknownEventType),
				errors.Is(err, parserErrors.ErrEventSkipped),
				// silently ignore perf ring buffer events with unknown types,
				// since they are not intended for us (e.g. MessageTypeRecCapture)
				parserErrors.IsErrInvalidType(err):
			default:
				s.log.WithError(err).WithField("event", monitorEvent).Debug("failed to decode payload")
			}
			continue
		}

		if flow, ok := ev.Event.(*flowpb.Flow); ok {
			// track namespaces seen.
			s.trackNamespaces(flow)
			for _, f := range s.opts.OnDecodedFlow {
				stop, err := f.OnDecodedFlow(ctx, flow)
				if err != nil {
					s.log.WithError(err).WithField("event", monitorEvent).Info("failed in OnDecodedFlow")
				}
				if stop {
					continue nextEvent
				}
			}

			s.numObservedFlows.Add(1)
		}

		for _, f := range s.opts.OnDecodedEvent {
			stop, err := f.OnDecodedEvent(ctx, ev)
			if err != nil {
				s.log.WithError(err).WithField("event", ev).Info("failed in OnDecodedEvent")
			}
			if stop {
				continue nextEvent
			}
		}
		if err := s.eventBuffer.Write(ev); err != nil {
			s.log.WithError(err).WithField("event", ev).Info("failed in eventBuffer.Write")
		}
	}
	close(s.GetStopped())
}

// GetEventsChannel returns the event channel to receive flowpb.Payload events.
func (s *LocalObserverServer) GetEventsChannel() chan *observerTypes.MonitorEvent {
	return s.events
}

// GetLogger implements GRPCServer.GetLogger.
func (s *LocalObserverServer) GetLogger() logrus.FieldLogger {
	return s.log
}

// GetStopped implements GRPCServer.GetStopped.
func (s *LocalObserverServer) GetStopped() chan struct{} {
	return s.stopped
}

// GetPayloadParser implements GRPCServer.GetPayloadParser.
func (s *LocalObserverServer) GetPayloadParser() *parser.Parser {
	return s.payloadParser
}

// GetOptions implements serveroptions.Server.GetOptions.
func (s *LocalObserverServer) GetOptions() observeroption.Options {
	return s.opts
}

// ServerStatus should have a comment, apparently. It returns the server status.
func (s *LocalObserverServer) ServerStatus(
	ctx context.Context, req *observerpb.ServerStatusRequest,
) (*observerpb.ServerStatusResponse, error) {
	return &observerpb.ServerStatusResponse{
		Version: build.ServerVersion.String(),
		// MaxFlows:  s.GetRingBuffer().Cap(),
		// NumFlows:  s.GetRingBuffer().Len(),
		SeenFlows: s.numObservedFlows.Load(),
		UptimeNs:  uint64(time.Since(s.startTime).Nanoseconds()),
	}, nil
}

// GetNodes implements observerpb.ObserverClient.GetNodes.
func (s *LocalObserverServer) GetNodes(ctx context.Context, req *observerpb.GetNodesRequest) (*observerpb.GetNodesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetNodes not implemented")
}

// GetNamespaces implements observerpb.ObserverClient.GetNamespaces.
func (s *LocalObserverServer) GetNamespaces(ctx context.Context, req *observerpb.GetNamespacesRequest) (*observerpb.GetNamespacesResponse, error) {
	return &observerpb.GetNamespacesResponse{Namespaces: s.namespaceManager.GetNamespaces()}, nil
}

// GetFlows implements the proto method for client requests.
func (s *LocalObserverServer) GetFlows(
	req *observerpb.GetFlowsRequest,
	server observerpb.Observer_GetFlowsServer,
) (err error) {
	if err := validateRequest(req); err != nil {
		return err
	}
	// This context is used for goroutines spawned specifically to serve this
	// request, meaning it must be cancelled once the request is done and this
	// function returns.
	ctx, cancel := context.WithCancel(server.Context())
	defer cancel()

	for _, f := range s.opts.OnGetFlows {
		ctx, err = f.OnGetFlows(ctx, req)
		if err != nil {
			return err
		}
	}

	filterList := append(filters.DefaultFilters, s.opts.OnBuildFilter...)
	whitelist, err := filters.BuildFilterList(ctx, req.Whitelist, filterList)
	if err != nil {
		return err
	}
	blacklist, err := filters.BuildFilterList(ctx, req.Blacklist, filterList)
	if err != nil {
		return err
	}

	start := time.Now()
	log := s.GetLogger()

	i := uint64(0)
	defer func() {
		log.WithFields(logrus.Fields{
			"number_of_flows": i,
			"whitelist":       logFilters(req.Whitelist),
			"blacklist":       logFilters(req.Blacklist),
			"took":            time.Since(start),
		}).Debug("GetFlows finished")
	}()

	eventsReader, err := newEventsReader(s.eventBuffer, req, log, whitelist, blacklist)
	if err != nil {
		return err
	}

	mask, err := fieldmask.New(req.Experimental.GetFieldMask())
	if err != nil {
		return err
	}

	var flow *flowpb.Flow
	if mask.Active() {
		flow = new(flowpb.Flow)
		mask.Alloc(flow.ProtoReflect())
	}

nextEvent:
	for ; ; i++ {
		e, err := eventsReader.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		var resp *observerpb.GetFlowsResponse

		switch ev := e.Event.(type) {
		case *flowpb.Flow:
			// eventsReader.eventCount++
			for _, f := range s.opts.OnFlowDelivery {
				stop, err := f.OnFlowDelivery(ctx, ev)
				switch {
				case err != nil:
					return err
				case stop:
					continue nextEvent
				}
			}
			if mask.Active() {
				// Copy only fields in the mask
				mask.Copy(flow.ProtoReflect(), ev.ProtoReflect())
				ev = flow
			}
			resp = &observerpb.GetFlowsResponse{
				Time:     ev.GetTime(),
				NodeName: ev.GetNodeName(),
				ResponseTypes: &observerpb.GetFlowsResponse_Flow{
					Flow: ev,
				},
			}
		case *flowpb.LostEvent:
			// Don't increment eventsReader.eventCount as a LostEvent is an
			// event type that is never explicitly requested by the user (e.g.
			// when a query asks for 20 events, then lost events should not be
			// accounted for as they are not events per se but an indication
			// that some event was lost).
			resp = &observerpb.GetFlowsResponse{
				Time:     e.Timestamp,
				NodeName: nodeTypes.GetAbsoluteNodeName(),
				ResponseTypes: &observerpb.GetFlowsResponse_LostEvents{
					LostEvents: ev,
				},
			}
		}

		if resp == nil {
			continue
		}

		err = server.Send(resp)
		if err != nil {
			return err
		}
	}
}

// GetAgentEvents implements observerpb.ObserverClient.GetAgentEvents.
func (s *LocalObserverServer) GetAgentEvents(
	req *observerpb.GetAgentEventsRequest,
	server observerpb.Observer_GetAgentEventsServer,
) (err error) {
	if err := validateRequest(req); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(server.Context())
	defer cancel()

	var whitelist, blacklist filters.FilterFuncs

	start := time.Now()
	log := s.GetLogger()

	i := uint64(0)
	defer func() {
		log.WithFields(logrus.Fields{
			"number_of_agent_events": i,
			"took":                   time.Since(start),
		}).Debug("GetAgentEvents finished")
	}()

	eventsReader, err := newEventsReader(s.eventBuffer, req, log, whitelist, blacklist)
	if err != nil {
		return err
	}

	for ; ; i++ {
		e, err := eventsReader.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		switch ev := e.Event.(type) {
		case *flowpb.AgentEvent:
			eventsReader.eventCount++
			resp := &observerpb.GetAgentEventsResponse{
				Time:       e.Timestamp,
				NodeName:   nodeTypes.GetAbsoluteNodeName(),
				AgentEvent: ev,
			}
			err = server.Send(resp)
			if err != nil {
				return err
			}
		}
	}
}

// GetDebugEvents implements observerpb.ObserverClient.GetDebugEvents.
func (s *LocalObserverServer) GetDebugEvents(
	req *observerpb.GetDebugEventsRequest,
	server observerpb.Observer_GetDebugEventsServer,
) (err error) {
	if err := validateRequest(req); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(server.Context())
	defer cancel()

	var whitelist, blacklist filters.FilterFuncs

	start := time.Now()
	log := s.GetLogger()

	i := uint64(0)
	defer func() {
		log.WithFields(logrus.Fields{
			"number_of_debug_events": i,
			"took":                   time.Since(start),
		}).Debug("GetDebugEvents finished")
	}()

	eventsReader, err := newEventsReader(s.eventBuffer, req, log, whitelist, blacklist)
	if err != nil {
		return err
	}

	for ; ; i++ {
		e, err := eventsReader.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		switch ev := e.Event.(type) {
		case *flowpb.DebugEvent:
			eventsReader.eventCount++
			resp := &observerpb.GetDebugEventsResponse{
				Time:       e.Timestamp,
				NodeName:   nodeTypes.GetAbsoluteNodeName(),
				DebugEvent: ev,
			}
			err = server.Send(resp)
			if err != nil {
				return err
			}
		}
	}
}

func logFilters(filters []*flowpb.FlowFilter) string {
	s := make([]string, 0, len(filters))
	for _, f := range filters {
		s = append(s, f.String())
	}
	return "{" + strings.Join(s, ",") + "}"
}

// genericRequest allows to abstract away generic request information for
// GetFlowsRequest, GetAgentEventsRequest and GetDebugEventsRequest.
type genericRequest interface {
	GetNumber() uint64
	GetFollow() bool
	GetSince() *timestamppb.Timestamp
	GetUntil() *timestamppb.Timestamp
	GetFirst() bool
}

var (
	_ genericRequest = (*observerpb.GetFlowsRequest)(nil)
	_ genericRequest = (*observerpb.GetAgentEventsRequest)(nil)
	_ genericRequest = (*observerpb.GetDebugEventsRequest)(nil)
)

// eventsReader reads flows using a RingReader. It applies the GetFlows request
// criteria (blacklist, whitelist, follow, ...) before returning events.
type eventsReader struct {
	eventIterator        container.EventIterator
	whitelist, blacklist filters.FilterFuncs
	maxEvents            uint64
	follow, timeRange    bool
	eventCount           uint64
	since, until         *time.Time
}

// newEventsReader creates a new eventsReader that uses the given EventReader to
// read through the events. Only events that match the request criteria
// are returned.
func newEventsReader(r container.EventReader, req genericRequest, log logrus.FieldLogger, whitelist, blacklist filters.FilterFuncs) (*eventsReader, error) {
	log.WithFields(logrus.Fields{
		"req":       req,
		"whitelist": whitelist,
		"blacklist": blacklist,
	}).Debug("creating a new eventsReader")

	since, until := req.GetSince(), req.GetUntil()
	reader := &eventsReader{
		eventIterator: r.Iterator(),
		whitelist:     whitelist,
		blacklist:     blacklist,
		maxEvents:     req.GetNumber(),
		follow:        req.GetFollow(),
		timeRange:     since != nil || until != nil,
	}

	if since != nil {
		if err := since.CheckValid(); err != nil {
			return nil, err
		}
		sinceTime := since.AsTime()
		reader.since = &sinceTime
	}

	if until != nil {
		if err := until.CheckValid(); err != nil {
			return nil, err
		}
		untilTime := until.AsTime()
		reader.until = &untilTime
	}

	return reader, nil
}

// Next returns the next event that matches the request criteria.
func (r *eventsReader) Next(ctx context.Context) (*v1.Event, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		var e *v1.Event
		var err error
		if r.follow {
			// TODO
		} else {
			if r.maxEvents > 0 && (r.eventCount >= r.maxEvents) {
				r.eventIterator.Close()
				return nil, io.EOF
			}
			e, err = r.eventIterator.Next()
			if err != nil {
				return nil, err
			}
		}
		if e == nil {
			return nil, io.EOF
		}

		// Treat LostEvent as a special case as callers will never explicitly
		// request them. This means that no regular filter nor time range
		// filter should be applied.
		// Note: lost events don't respect the assumption that "ring buffer
		// timestamps are supposed to be monotonic" as their timestamp
		// corresponds to when a LostEvent was detected.
		_, isLostEvent := e.Event.(*flowpb.LostEvent)
		if !isLostEvent {
			if r.timeRange {
				if err := e.Timestamp.CheckValid(); err != nil {
					return nil, err
				}
				ts := e.Timestamp.AsTime()

				if r.until != nil && ts.After(*r.until) {
					return nil, io.EOF
				}

				if r.since != nil && ts.Before(*r.since) {
					continue
				}
			}

			if !filters.Apply(r.whitelist, r.blacklist, e) {
				continue
			}
		}

		return e, nil
	}
}

func (s *LocalObserverServer) trackNamespaces(flow *flowpb.Flow) {
	// track namespaces seen.
	if srcNs := flow.GetSource().GetNamespace(); srcNs != "" {
		s.namespaceManager.AddNamespace(&observerpb.Namespace{
			Namespace: srcNs,
			Cluster:   nodeTypes.GetClusterName(),
		})
	}
	if dstNs := flow.GetDestination().GetNamespace(); dstNs != "" {
		s.namespaceManager.AddNamespace(&observerpb.Namespace{
			Namespace: dstNs,
			Cluster:   nodeTypes.GetClusterName(),
		})
	}
}

func validateRequest(req genericRequest) error {
	if req.GetFirst() && req.GetFollow() {
		return status.Errorf(codes.InvalidArgument, "first cannot be specified with follow")
	}
	return nil
}

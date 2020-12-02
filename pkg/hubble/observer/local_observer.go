// Copyright 2020 Authors of Hubble
// Copyright 2020 Authors of Cilium
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

package observer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/build"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	parserErrors "github.com/cilium/cilium/pkg/hubble/parser/errors"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultOptions to include in the server. Other packages may extend this
// in their init() function.
var DefaultOptions []observeroption.Option

// LocalObserverServer is an implementation of the server.Observer interface
// that's meant to be run embedded inside the Cilium process. It ignores all
// the state change events since the state is available locally.
type LocalObserverServer struct {
	// ring buffer that contains the references of all flows
	ring *container.Ring

	// events is the channel used by the writer(s) to send the flow data
	// into the observer server.
	events chan *observerTypes.MonitorEvent

	// stopped is mostly used in unit tests to signalize when the events
	// channel is empty, once it's closed.
	stopped chan struct{}

	log logrus.FieldLogger

	// channel to receive events from observer server.
	eventschan chan *observerpb.GetFlowsResponse

	// payloadParser decodes flowpb.Payload into flowpb.Flow
	payloadParser *parser.Parser

	opts observeroption.Options

	// startTime is the time when this instance was started
	startTime time.Time

	// numObservedFlows counts how many flows have been observed
	numObservedFlows uint64
}

// NewLocalServer returns a new local observer server.
func NewLocalServer(
	payloadParser *parser.Parser,
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
		"maxFlows":       opts.MaxFlows,
		"eventQueueSize": opts.MonitorBuffer,
	}).Info("Configuring Hubble server")

	s := &LocalObserverServer{
		log:           logger,
		ring:          container.NewRing(opts.MaxFlows),
		events:        make(chan *observerTypes.MonitorEvent, opts.MonitorBuffer),
		stopped:       make(chan struct{}),
		eventschan:    make(chan *observerpb.GetFlowsResponse, 100), // option here?
		payloadParser: payloadParser,
		startTime:     time.Now(),
		opts:          opts,
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
			if !errors.Is(err, parserErrors.ErrUnknownEventType) {
				s.log.WithError(err).WithField("event", monitorEvent).Debug("failed to decode payload")
			}
			continue
		}

		if flow, ok := ev.Event.(*flowpb.Flow); ok {
			for _, f := range s.opts.OnDecodedFlow {
				stop, err := f.OnDecodedFlow(ctx, flow)
				if err != nil {
					s.log.WithError(err).WithField("event", monitorEvent).Info("failed in OnDecodedFlow")
				}
				if stop {
					continue nextEvent
				}
			}

			atomic.AddUint64(&s.numObservedFlows, 1)
			// FIXME: Convert metrics into an OnDecodedFlow function
			metrics.ProcessFlow(flow)
		}

		s.GetRingBuffer().Write(ev)
	}
	close(s.GetStopped())
}

// GetEventsChannel returns the event channel to receive flowpb.Payload events.
func (s *LocalObserverServer) GetEventsChannel() chan *observerTypes.MonitorEvent {
	return s.events
}

// GetRingBuffer implements GRPCServer.GetRingBuffer.
func (s *LocalObserverServer) GetRingBuffer() *container.Ring {
	return s.ring
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
		Version:   build.ServerVersion.String(),
		MaxFlows:  s.GetRingBuffer().Cap(),
		NumFlows:  s.GetRingBuffer().Len(),
		SeenFlows: atomic.LoadUint64(&s.numObservedFlows),
		UptimeNs:  uint64(time.Since(s.startTime).Nanoseconds()),
	}, nil
}

// GetNodes implements observerpb.ObserverClient.GetNodes.
func (s *LocalObserverServer) GetNodes(ctx context.Context, req *observerpb.GetNodesRequest) (*observerpb.GetNodesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetNodes not implemented")
}

// GetFlows implements the proto method for client requests.
func (s *LocalObserverServer) GetFlows(
	req *observerpb.GetFlowsRequest,
	server observerpb.Observer_GetFlowsServer,
) (err error) {
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
	ring := s.GetRingBuffer()

	i := uint64(0)
	defer func() {
		log.WithFields(logrus.Fields{
			"number_of_flows": i,
			"buffer_size":     ring.Cap(),
			"whitelist":       logFilters(req.Whitelist),
			"blacklist":       logFilters(req.Blacklist),
			"took":            time.Since(start),
		}).Debug("GetFlows finished")
	}()

	ringReader, err := newRingReader(ring, req, whitelist, blacklist)
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	flowsReader, err := newFlowsReader(ringReader, req, log, whitelist, blacklist)
	if err != nil {
		return err
	}

nextFlow:
	for ; ; i++ {
		resp, err := flowsReader.Next(ctx)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		for _, f := range s.opts.OnFlowDelivery {
			stop, err := f.OnFlowDelivery(ctx, resp.GetFlow())
			if err != nil {
				return err
			}
			if stop {
				continue nextFlow
			}
		}

		err = server.Send(resp)
		if err != nil {
			return err
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

// flowsReader reads flows using a RingReader. It applies the flow request
// criteria (blacklist, whitelist, follow, ...) before returning flows.
type flowsReader struct {
	ringReader           *container.RingReader
	whitelist, blacklist filters.FilterFuncs
	maxFlows             uint64
	follow, timeRange    bool
	flowsCount           uint64
	since, until         *time.Time
}

// newFlowsReader creates a new flowsReader that uses the given RingReader to
// read through the ring buffer. Only flows that match the request criteria
// are returned.
func newFlowsReader(r *container.RingReader, req *observerpb.GetFlowsRequest, log logrus.FieldLogger, whitelist, blacklist filters.FilterFuncs) (*flowsReader, error) {
	log.WithFields(logrus.Fields{
		"req":       req,
		"whitelist": whitelist,
		"blacklist": blacklist,
	}).Debug("creating a new flowsReader")

	reader := &flowsReader{
		ringReader: r,
		whitelist:  whitelist,
		blacklist:  blacklist,
		maxFlows:   req.Number,
		follow:     req.Follow,
		timeRange:  req.Since != nil || req.Until != nil,
	}

	if req.Since != nil {
		since, err := ptypes.Timestamp(req.Since)
		if err != nil {
			return nil, err
		}
		reader.since = &since
	}

	if req.Until != nil {
		until, err := ptypes.Timestamp(req.Until)
		if err != nil {
			return nil, err
		}
		reader.until = &until
	}

	return reader, nil
}

// Next returns the next flow that matches the request criteria.
func (r *flowsReader) Next(ctx context.Context) (*observerpb.GetFlowsResponse, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		var e *v1.Event
		var err error
		if r.follow {
			e = r.ringReader.NextFollow(ctx)
		} else {
			if r.maxFlows > 0 && (r.flowsCount >= r.maxFlows) {
				return nil, io.EOF
			}
			e, err = r.ringReader.Next()
			if err != nil {
				if errors.Is(err, container.ErrInvalidRead) {
					// this error is sent over the wire and presented to the user
					return nil, errors.New("requested data has been overwritten and is no longer available")
				}
				return nil, err
			}
		}
		if e == nil {
			return nil, io.EOF
		}

		if r.timeRange {
			ts, err := ptypes.Timestamp(e.Timestamp)
			if err != nil {
				return nil, err
			}

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

		switch ev := e.Event.(type) {
		case *flowpb.Flow:
			r.flowsCount++
			return &observerpb.GetFlowsResponse{
				Time:     ev.GetTime(),
				NodeName: ev.GetNodeName(),
				ResponseTypes: &observerpb.GetFlowsResponse_Flow{
					Flow: ev,
				},
			}, nil
		case *flowpb.LostEvent:
			return &observerpb.GetFlowsResponse{
				Time:     e.Timestamp,
				NodeName: nodeTypes.GetName(),
				ResponseTypes: &observerpb.GetFlowsResponse_LostEvents{
					LostEvents: ev,
				},
			}, nil
		case *flowpb.AgentEvent:
			return &observerpb.GetFlowsResponse{
				Time:     e.Timestamp,
				NodeName: nodeTypes.GetName(),
				ResponseTypes: &observerpb.GetFlowsResponse_AgentEvent{
					AgentEvent: ev,
				},
			}, nil
		}
	}
}

// newRingReader creates a new RingReader that starts at the correct ring
// offset to match the flow request.
func newRingReader(ring *container.Ring, req *observerpb.GetFlowsRequest, whitelist, blacklist filters.FilterFuncs) (*container.RingReader, error) {
	if req.Follow && req.Number == 0 && req.Since == nil {
		// no need to rewind
		return container.NewRingReader(ring, ring.LastWriteParallel()), nil
	}

	var err error
	var since time.Time
	if req.Since != nil {
		since, err = ptypes.Timestamp(req.Since)
		if err != nil {
			return nil, err
		}
	}

	idx := ring.LastWriteParallel()
	reader := container.NewRingReader(ring, idx)

	var flowsCount uint64
	// We need to find out what the right index is; that is the index with the
	// oldest entry that is within time range boundaries (if any is defined)
	// or until we find enough events.
	// In order to avoid buffering events, we have to rewind first to find the
	// correct index, then create a new reader that starts from there
	for i := ring.Len(); i > 0; i, idx = i-1, idx-1 {
		e, err := reader.Previous()
		if errors.Is(err, container.ErrInvalidRead) {
			idx++ // we went backward 1 too far
			break
		} else if err != nil {
			return nil, err
		}
		_, ok := e.Event.(*flowpb.Flow)
		if !ok || !filters.Apply(whitelist, blacklist, e) {
			continue
		}
		flowsCount++
		if req.Since != nil {
			ts, err := ptypes.Timestamp(e.Timestamp)
			if err != nil {
				return nil, err
			}
			if ts.Before(since) {
				idx++ // we went backward 1 too far
				break
			}
		} else if flowsCount == req.Number {
			break // we went backward far enough
		}
	}
	return container.NewRingReader(ring, idx), nil
}

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
	"time"

	pb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/hubble/parser"
	parserErrors "github.com/cilium/cilium/pkg/hubble/parser/errors"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
)

// DefaultOptions to include in the server. Other packages may extend this
// in their init() function.
var DefaultOptions []observeroption.Option

// GRPCServer defines the interface for Hubble gRPC server, extending the
// auto-generated ObserverServer interface from the protobuf definition.
type GRPCServer interface {
	observerpb.ObserverServer
	// Start starts the server and blocks.
	Start()
	// GetEventsChannel returns the channel to push monitor events to.
	GetEventsChannel() chan *pb.Payload
	// SetEventsChannel sets the events channel. For unit testing only.
	SetEventsChannel(chan *pb.Payload)
	///GetRingBuffer returns the underlying ring buffer to parsed events.
	GetRingBuffer() *container.Ring
	// GetStopped returns a channel that gets closed at the end of the
	// main server loop after all the events have been processes. Used
	// in unit testing.
	GetStopped() chan struct{}
	// GetLogger returns the logger assigned to this gRPC server.
	GetLogger() *logrus.Entry
}

// LocalObserverServer is an implementation of the server.Observer interface
// that's meant to be run embedded inside the Cilium process. It ignores all
// the state change events since the state is available locally.
type LocalObserverServer struct {
	// ring buffer that contains the references of all flows
	ring *container.Ring

	// events is the channel used by the writer(s) to send the flow data
	// into the observer server.
	events chan *pb.Payload

	// stopped is mostly used in unit tests to signalize when the events
	// channel is empty, once it's closed.
	stopped chan struct{}

	log *logrus.Entry

	// channel to receive events from observer server.
	eventschan chan *observerpb.GetFlowsResponse

	// payloadParser decodes pb.Payload into pb.Flow
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
	logger *logrus.Entry,
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
		events:        make(chan *pb.Payload, opts.MonitorBuffer),
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
	for pl := range s.GetEventsChannel() {
		for _, f := range s.opts.OnMonitorEvent {
			stop, err := f.OnMonitorEvent(ctx, pl)
			if err != nil {
				s.log.WithError(err).WithField("data", pl.Data).Info("failed in OnMonitorEvent")
			}
			if stop {
				continue nextEvent
			}
		}

		flow, err := decodeFlow(s.payloadParser, pl)
		if err != nil {
			if !parserErrors.IsErrInvalidType(err) {
				s.log.WithError(err).WithField("data", pl.Data).Debug("failed to decode payload")
			}
			continue
		}

		for _, f := range s.opts.OnDecodedFlow {
			stop, err := f.OnDecodedFlow(ctx, flow)
			if err != nil {
				s.log.WithError(err).WithField("data", pl.Data).Info("failed in OnDecodedFlow")
			}
			if stop {
				continue nextEvent
			}
		}

		s.numObservedFlows++
		// FIXME: Convert metrics into an OnDecodedFlow function
		metrics.ProcessFlow(flow)

		s.GetRingBuffer().Write(&v1.Event{
			Timestamp: pl.Time,
			Event:     flow,
		})
	}
	close(s.GetStopped())
}

// GetEventsChannel returns the event channel to receive pb.Payload events.
func (s *LocalObserverServer) GetEventsChannel() chan *pb.Payload {
	return s.events
}

// SetEventsChannel implements GRPCServer.SetEventsChannel.
func (s *LocalObserverServer) SetEventsChannel(events chan *pb.Payload) {
	s.events = events
}

// GetRingBuffer implements GRPCServer.GetRingBuffer.
func (s *LocalObserverServer) GetRingBuffer() *container.Ring {
	return s.ring
}

// GetLogger implements GRPCServer.GetLogger.
func (s *LocalObserverServer) GetLogger() *logrus.Entry {
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
		MaxFlows:  s.GetRingBuffer().Cap(),
		NumFlows:  s.GetRingBuffer().Len(),
		SeenFlows: s.numObservedFlows,
		UptimeNs:  uint64(time.Since(s.startTime).Nanoseconds()),
	}, nil
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
			"took":            time.Now().Sub(start),
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
		flow, err := flowsReader.Next(ctx)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		for _, f := range s.opts.OnFlowDelivery {
			stop, err := f.OnFlowDelivery(ctx, flow)
			if err != nil {
				return err
			}
			if stop {
				continue nextFlow
			}
		}

		err = server.Send(&observerpb.GetFlowsResponse{
			Time:     flow.GetTime(),
			NodeName: flow.GetNodeName(),
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{
				Flow: flow,
			},
		})
		if err != nil {
			return err
		}
	}
}

func getUntil(req *observerpb.GetFlowsRequest, defaultTime *timestamp.Timestamp) (time.Time, error) {
	until := req.GetUntil()
	if until == nil {
		until = defaultTime
	}
	return ptypes.Timestamp(until)
}

func logFilters(filters []*pb.FlowFilter) string {
	var s []string
	for _, f := range filters {
		s = append(s, f.String())
	}
	return "{" + strings.Join(s, ",") + "}"
}

func decodeFlow(payloadParser *parser.Parser, pl *pb.Payload) (*pb.Flow, error) {
	// TODO: Pool these instead of allocating new flows each time.
	f := &pb.Flow{}
	err := payloadParser.Decode(pl, f)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// flowsReader reads flows using a RingReader. It applies the flow request
// criterias (blacklist, whitelist, follow, ...) before returning flows.
type flowsReader struct {
	ringReader           *container.RingReader
	whitelist, blacklist filters.FilterFuncs
	maxFlows             uint64
	follow, timeRange    bool
	flowsCount           uint64
	start, end           time.Time
}

// newFlowsReader creates a new flowsReader that uses the given RingReader to
// read through the ring buffer. Only flows that match the request criterias
// are returned.
func newFlowsReader(r *container.RingReader, req *observerpb.GetFlowsRequest, log *logrus.Entry, whitelist, blacklist filters.FilterFuncs) (*flowsReader, error) {
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
		timeRange:  !req.Follow && req.Number == 0,
	}
	if reader.timeRange { // apply time range filtering
		var err error
		reader.start, err = ptypes.Timestamp(req.GetSince())
		if err != nil {
			return nil, err
		}
		reader.end, err = getUntil(req, ptypes.TimestampNow())
		if err != nil {
			return nil, err
		}
	}
	return reader, nil
}

// Next returns the next flow that matches the request criterias.
func (r *flowsReader) Next(ctx context.Context) (*pb.Flow, error) {
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
				if err == container.ErrInvalidRead {
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
			ts, err := ptypes.Timestamp(e.GetFlow().GetTime())
			if err != nil {
				return nil, err
			}
			if ts.After(r.end) {
				return nil, io.EOF
			}
			if ts.Before(r.start) {
				continue
			}
		}
		flow, ok := e.Event.(*pb.Flow)
		if ok && filters.Apply(r.whitelist, r.blacklist, e) {
			r.flowsCount++
			return flow, nil
		}
	}
}

// newRingReader creates a new RingReader that starts at the correct ring
// offset to match the flow request.
func newRingReader(ring *container.Ring, req *observerpb.GetFlowsRequest, whitelist, blacklist filters.FilterFuncs) (*container.RingReader, error) {
	if req.Follow && req.Number == 0 { // no need to rewind
		return container.NewRingReader(ring, ring.LastWriteParallel()), nil
	}

	var err error
	var start time.Time
	since := req.GetSince()
	if since != nil {
		start, err = ptypes.Timestamp(since)
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
		if err == container.ErrInvalidRead {
			idx++ // we went backward 1 too far
			break
		} else if err != nil {
			return nil, err
		}
		_, ok := e.Event.(*pb.Flow)
		if !ok || !filters.Apply(whitelist, blacklist, e) {
			continue
		}
		flowsCount++
		if since != nil {
			ts, err := ptypes.Timestamp(e.GetFlow().GetTime())
			if err != nil {
				return nil, err
			}
			if ts.Before(start) {
				idx++ // we went backward 1 too far
				break
			}
		} else if flowsCount == req.Number {
			break // we went backward far enough
		}
	}
	return container.NewRingReader(ring, idx), nil
}

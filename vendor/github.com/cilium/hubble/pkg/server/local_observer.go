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

package server

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/math"
	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/api/v1/observer"
	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/container"
	"github.com/cilium/hubble/pkg/filters"
	"github.com/cilium/hubble/pkg/metrics"
	"github.com/cilium/hubble/pkg/parser"
	"github.com/cilium/hubble/pkg/parser/errors"
	"github.com/gogo/protobuf/types"
	"github.com/sirupsen/logrus"
)

// GRPCServer defines the interface for Hubble gRPC server, extending the
// auto-generated ObserverServer interface from the protobuf definition.
type GRPCServer interface {
	observer.ObserverServer
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
	eventschan chan *observer.GetFlowsResponse

	// payloadParser decodes pb.Payload into pb.Flow
	payloadParser *parser.Parser
}

// NewLocalServer returns a new local observer server.
func NewLocalServer(
	payloadParser *parser.Parser,
	maxFlows int,
	logger *logrus.Entry,
) *LocalObserverServer {
	return &LocalObserverServer{
		log:  logger,
		ring: container.NewRing(maxFlows),
		// have a channel with 1% of the max flows that we can receive
		events:        make(chan *pb.Payload, uint64(math.IntMin(maxFlows/100, 100))),
		stopped:       make(chan struct{}),
		eventschan:    make(chan *observer.GetFlowsResponse, 100),
		payloadParser: payloadParser,
	}
}

// Start implements GRPCServer.Start.
func (s *LocalObserverServer) Start() {
	for pl := range s.GetEventsChannel() {
		flow, err := decodeFlow(s.payloadParser, pl)
		if err != nil {
			if !errors.IsErrInvalidType(err) {
				s.log.WithError(err).WithField("data", pl.Data).Debug("failed to decode payload")
			}
			continue
		}

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

// ServerStatus should have a comment, apparently. It returns the server status.
func (s *LocalObserverServer) ServerStatus(
	ctx context.Context, req *observer.ServerStatusRequest,
) (*observer.ServerStatusResponse, error) {
	return &observer.ServerStatusResponse{
		MaxFlows: s.GetRingBuffer().Cap(),
		NumFlows: s.GetRingBuffer().Len(),
	}, nil
}

// GetFlows implements the proto method for client requests.
func (s *LocalObserverServer) GetFlows(
	req *observer.GetFlowsRequest,
	server observer.Observer_GetFlowsServer,
) (err error) {
	return getFlows(req, server, s)
}

func getFlows(
	req *observer.GetFlowsRequest,
	server observer.Observer_GetFlowsServer,
	obs GRPCServer,
) (err error) {
	start := time.Now()
	log := obs.GetLogger()
	ring := obs.GetRingBuffer()

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

	ringReader, err := newRingReader(ring, req)
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	flowsReader, err := newFlowsReader(ringReader, req, log)
	if err != nil {
		return err
	}

	for ; ; i++ {
		flow, err := flowsReader.Next(server.Context())
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		err = server.Send(&observer.GetFlowsResponse{
			ResponseTypes: &observer.GetFlowsResponse_Flow{
				Flow: flow,
			},
		})
		if err != nil {
			return err
		}
	}
}

func getUntil(req *observer.GetFlowsRequest, defaultTime *types.Timestamp) (time.Time, error) {
	until := req.GetUntil()
	if until == nil {
		until = defaultTime
	}
	return types.TimestampFromProto(until)
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
func newFlowsReader(r *container.RingReader, req *observer.GetFlowsRequest, log *logrus.Entry) (*flowsReader, error) {
	whitelist, err := filters.BuildFilterList(req.Whitelist)
	if err != nil {
		return nil, err
	}
	blacklist, err := filters.BuildFilterList(req.Blacklist)
	if err != nil {
		return nil, err
	}

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
		reader.start, err = types.TimestampFromProto(req.GetSince())
		if err != nil {
			return nil, err
		}
		reader.end, err = getUntil(req, types.TimestampNow())
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
		if r.follow {
			e = r.ringReader.NextFollow(ctx)
		} else {
			if r.maxFlows > 0 && (r.flowsCount >= r.maxFlows) {
				return nil, io.EOF
			}
			e = r.ringReader.Next()
		}
		if e == nil {
			return nil, io.EOF
		}
		flow, ok := e.Event.(*pb.Flow)
		if ok && filters.Apply(r.whitelist, r.blacklist, e) {
			if r.timeRange {
				ts, err := types.TimestampFromProto(e.GetFlow().GetTime())
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
			r.flowsCount++
			return flow, nil
		}
	}
}

// newRingReader creates a new RingReader that starts at the correct ring
// offset to match the flow request.
func newRingReader(ring *container.Ring, req *observer.GetFlowsRequest) (*container.RingReader, error) {
	if req.Follow && req.Number == 0 { // no need to rewind
		return container.NewRingReader(ring, ring.LastWriteParallel()), nil
	}

	var err error
	var start time.Time
	since := req.GetSince()
	if since != nil {
		start, err = types.TimestampFromProto(since)
		if err != nil {
			return nil, err
		}
	}
	whitelist, err := filters.BuildFilterList(req.Whitelist)
	if err != nil {
		return nil, err
	}
	blacklist, err := filters.BuildFilterList(req.Blacklist)
	if err != nil {
		return nil, err
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
		e := reader.Previous()
		if e == nil {
			break
		}
		_, ok := e.Event.(*pb.Flow)
		if !ok || !filters.Apply(whitelist, blacklist, e) {
			continue
		}
		flowsCount++
		if since != nil {
			ts, err := types.TimestampFromProto(e.GetFlow().GetTime())
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

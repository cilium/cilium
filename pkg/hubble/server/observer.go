// Copyright 2019-2020 Authors of Hubble
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
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hubble/api"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/cilium"
	"github.com/cilium/cilium/pkg/hubble/cilium/client"
	"github.com/cilium/cilium/pkg/hubble/ipcache"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/hubble/servicecache"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"

	types "github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
)

// ObserverServer is a server that can store events in memory
type ObserverServer struct {
	// grpcServer is responsible for caching events and serving gRPC requests.
	grpcServer GRPCServer

	ciliumState *cilium.State

	log *logrus.Entry
}

// NewServer returns a server that can store up to the given of maxFlows
// received.
func NewServer(
	ciliumClient client.Client,
	endpoints v1.EndpointsHandler,
	ipCache *ipcache.IPCache,
	fqdnCache cilium.FqdnCache,
	serviceCache *servicecache.ServiceCache,
	payloadParser *parser.Parser,
	maxFlows int,
	eventQueueSize int,
	logger *logrus.Entry,
) (*ObserverServer, error) {
	ciliumState := cilium.NewCiliumState(ciliumClient, endpoints, ipCache, fqdnCache, serviceCache, logger)
	s, err := NewLocalServer(
		payloadParser, logger,
		serveroption.WithMaxFlows(maxFlows),
		serveroption.WithMonitorBuffer(eventQueueSize),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create local server: %v", err)
	}
	return &ObserverServer{
		log:         logger,
		grpcServer:  s,
		ciliumState: ciliumState,
	}, nil
}

// Start starts the server to handle the events sent to the events channel as
// well as handle events to the EpAdd and EpDel channels.
func (s *ObserverServer) Start() {
	go s.ciliumState.Start()
	go s.GetGRPCServer().Start()
}

// HandleMonitorSocket connects to the monitor socket and consumes monitor events.
func (s *ObserverServer) HandleMonitorSocket(ctx context.Context, nodeName string) error {
	// On EOF, retry
	// On other errors and done ctx, exit
	// always wait connTimeout when retrying
	for {
		conn, version, err := openMonitorSock()
		if err != nil {
			s.log.WithError(err).Error("Cannot open monitor serverSocketPath")
			return err
		}

		err = s.consumeMonitorEvents(ctx, conn, version, nodeName)
		switch err {
		case nil:
			// no-op
		case io.EOF, io.ErrUnexpectedEOF:
			s.log.WithError(err).Warn("connection closed")
		default:
			return fmt.Errorf("decoding error: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(api.ConnectionTimeout):
		}
	}
}

// getMonitorParser constructs and returns an eventParserFunc. It is
// appropriate for the monitor API version passed in.
func getMonitorParser(conn net.Conn, version listener.Version, nodeName string) (parser eventParserFunc, err error) {
	switch version {
	case listener.Version1_2:
		var (
			pl  payload.Payload
			dec = gob.NewDecoder(conn)
		)
		// This implements the newer 1.2 API. Each listener maintains its own gob
		// session, and type information is only ever sent once.
		return func() (*pb.Payload, error) {
			if err := pl.DecodeBinary(dec); err != nil {
				return nil, err
			}
			b := make([]byte, len(pl.Data))
			copy(b, pl.Data)

			// TODO: Eventually, the monitor will add these timestaps to events.
			// For now, we add them in hubble server.
			grpcPl := &pb.Payload{
				Data:     b,
				CPU:      int32(pl.CPU),
				Lost:     pl.Lost,
				Type:     pb.EventType(pl.Type),
				Time:     types.TimestampNow(),
				HostName: nodeName,
			}
			return grpcPl, nil
		}, nil

	default:
		return nil, fmt.Errorf("unsupported version %s", version)
	}
}

// consumeMonitorEvents handles and prints events on a monitor connection. It
// calls getMonitorParsed to construct a monitor-version appropriate parser.
// It closes conn on return, and returns on error, including io.EOF
func (s *ObserverServer) consumeMonitorEvents(ctx context.Context, conn net.Conn, version listener.Version, nodeName string) error {
	defer conn.Close()
	ch := s.GetGRPCServer().GetEventsChannel()
	endpointEvents := s.ciliumState.GetEndpointEventsChannel()

	dnsAdd := s.ciliumState.GetLogRecordNotifyChannel()

	ipCacheEvents := make(chan monitorAPI.AgentNotify, 100)
	s.ciliumState.StartMirroringIPCache(ipCacheEvents)

	serviceEvents := make(chan monitorAPI.AgentNotify, 100)
	s.ciliumState.StartMirroringServiceCache(serviceEvents)

	getParsedPayload, err := getMonitorParser(conn, version, nodeName)
	if err != nil {
		return err
	}

	for {
		pl, err := getParsedPayload()
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case ch <- pl:
		}

		// we don't expect to have many MessageTypeAgent so we
		// can "decode" this messages as they come.
		switch pl.Data[0] {
		case monitorAPI.MessageTypeAgent:
			buf := bytes.NewBuffer(pl.Data[1:])
			dec := gob.NewDecoder(buf)

			an := monitorAPI.AgentNotify{}
			if err := dec.Decode(&an); err != nil {
				s.log.WithError(err).Warning("failed to decoded agent notification message")
				continue
			}
			switch an.Type {
			case monitorAPI.AgentNotifyEndpointCreated,
				monitorAPI.AgentNotifyEndpointRegenerateSuccess,
				monitorAPI.AgentNotifyEndpointDeleted:
				endpointEvents <- an
			case monitorAPI.AgentNotifyIPCacheUpserted,
				monitorAPI.AgentNotifyIPCacheDeleted:
				ipCacheEvents <- an
			case monitorAPI.AgentNotifyServiceUpserted,
				monitorAPI.AgentNotifyServiceDeleted:
				serviceEvents <- an
			}
		case monitorAPI.MessageTypeAccessLog:
			// TODO re-think the way this is being done. We are dissecting/
			//      TypeAccessLog messages here *and* when we are dumping
			//      them into JSON.
			buf := bytes.NewBuffer(pl.Data[1:])
			dec := gob.NewDecoder(buf)

			lr := monitor.LogRecordNotify{}

			if err := dec.Decode(&lr); err != nil {
				s.log.WithError(err).Warning("failed to decode access logg message type")
				continue
			}
			if lr.DNS != nil {
				dnsAdd <- lr
			}
		}
	}
}

// eventParseFunc is a convenience function type used as a version-specific
// parser of monitor events
type eventParserFunc func() (*pb.Payload, error)

// openMonitorSock attempts to open a version specific monitor serverSocketPath It
// returns a connection, with a version, or an error.
func openMonitorSock() (conn net.Conn, version listener.Version, err error) {
	errors := make([]string, 0)

	// try the 1.2 serverSocketPath
	conn, err = net.Dial("unix", defaults.MonitorSockPath1_2)
	if err == nil {
		return conn, listener.Version1_2, nil
	}
	errors = append(errors, defaults.MonitorSockPath1_2+": "+err.Error())

	return nil, listener.VersionUnsupported, fmt.Errorf("cannot find or open a supported node-monitor serverSocketPath. %s", strings.Join(errors, ","))
}

// GetGRPCServer returns the GRPCServer embedded in this ObserverServer.
func (s *ObserverServer) GetGRPCServer() GRPCServer {
	return s.grpcServer
}

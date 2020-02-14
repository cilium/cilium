// Copyright 2019-2020 Authors of Cilium
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
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/api"
	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/hubble/pkg/cilium/client"
	"github.com/cilium/hubble/pkg/ipcache"
	"github.com/cilium/hubble/pkg/parser"
	"github.com/cilium/hubble/pkg/servicecache"
	"github.com/gogo/protobuf/types"
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
	logger *logrus.Entry,
) *ObserverServer {
	ciliumState := cilium.NewCiliumState(ciliumClient, endpoints, ipCache, fqdnCache, serviceCache, logger)
	return &ObserverServer{
		log:         logger,
		grpcServer:  NewLocalServer(payloadParser, maxFlows, logger),
		ciliumState: ciliumState,
	}
}

// Start starts the server to handle the events sent to the events channel as
// well as handle events to the EpAdd and EpDel channels.
func (s *ObserverServer) Start() {
	go s.ciliumState.Start()
	go s.GetGRPCServer().Start()
}

// HandleMonitorSocket connects to the monitor socket and consumes monitor events.
func (s *ObserverServer) HandleMonitorSocket(nodeName string) error {
	// On EOF, retry
	// On other errors, exit
	// always wait connTimeout when retrying
	for ; ; time.Sleep(api.ConnectionTimeout) {
		conn, version, err := openMonitorSock()
		if err != nil {
			s.log.WithError(err).Error("Cannot open monitor serverSocketPath")
			return err
		}

		err = s.consumeMonitorEvents(conn, version, nodeName)
		switch {
		case err == nil:
			// no-op

		case err == io.EOF, err == io.ErrUnexpectedEOF:
			s.log.WithError(err).Warn("connection closed")
			continue

		default:
			s.log.WithError(err).Fatal("decoding error")
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
func (s *ObserverServer) consumeMonitorEvents(conn net.Conn, version listener.Version, nodeName string) error {
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

		ch <- pl
		// we don't expect to have many MessageTypeAgent so we
		// can "decode" this messages as they come.
		switch pl.Data[0] {
		case monitorAPI.MessageTypeAgent:
			buf := bytes.NewBuffer(pl.Data[1:])
			dec := gob.NewDecoder(buf)

			an := monitorAPI.AgentNotify{}
			if err := dec.Decode(&an); err != nil {
				fmt.Printf("Error while decoding agent notification message: %s\n", err)
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
				fmt.Printf("Error while decoding access log message type: %s\n", err)
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

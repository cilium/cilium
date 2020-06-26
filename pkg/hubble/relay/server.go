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

package relay

import (
	"fmt"
	"net"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/relay/relayoption"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// Server is a proxy that connects to a running instance of hubble gRPC server
// via unix domain socket.
type Server struct {
	server *grpc.Server
	ps     peerSyncer
	log    logrus.FieldLogger
	opts   relayoption.Options
	stop   chan struct{}
}

// NewServer creates a new hubble-relay Server.
func NewServer(options ...relayoption.Option) (*Server, error) {
	opts := relayoption.Default
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay")
	logging.ConfigureLogLevel(opts.Debug)
	return &Server{
		ps:   newSyncer(opts.HubbleTarget, opts.DialTimeout, opts.RetryTimeout, logger),
		log:  logger,
		stop: make(chan struct{}),
		opts: opts,
	}, nil
}

// Serve starts the hubble-relay server. Serve does not return unless a
// listening fails with fatal errors. Serve will return a non-nil error if
// Stop() is not called.
func (s *Server) Serve() error {
	s.log.WithField("options", fmt.Sprintf("%+v", s.opts)).Info("Starting server...")
	s.server = grpc.NewServer()
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus(v1.ObserverServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s.server, healthSrv)
	observerpb.RegisterObserverServer(s.server, s)
	socket, err := net.Listen("tcp", s.opts.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on tcp socket %s: %v", s.opts.ListenAddress, err)
	}
	s.ps.Start()
	reflection.Register(s.server)
	return s.server.Serve(socket)
}

// Stop terminates the hubble-relay server.
func (s *Server) Stop() {
	s.log.Info("Stopping server...")
	close(s.stop)
	s.server.Stop()
	s.ps.Stop()
	s.log.Info("Server stopped")
}

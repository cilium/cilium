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
	"errors"
	"fmt"
	"net"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/relay/observer"
	"github.com/cilium/cilium/pkg/hubble/relay/pool"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	// ErrNoTransportCredentials is returned when no transport credentials is
	// set for the server unless WithInsecureServer() is provided.
	ErrNoTransportCredentials = errors.New("no transport credentials configured")

	// ErrNoClientTLSConfig is returned when no client TLS config is set unless
	// WithInsecureClient() is provided.
	ErrNoClientTLSConfig = errors.New("no client TLS config is set")
)

// Server is a proxy that connects to a running instance of hubble gRPC server
// via unix domain socket.
type Server struct {
	server *grpc.Server
	pm     *pool.PeerManager
	log    logrus.FieldLogger
	opts   options
	stop   chan struct{}
}

// New creates a new Server.
func New(options ...Option) (*Server, error) {
	opts := defaultOptions
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	if opts.clientTLSConfig == nil && !opts.insecure {
		return nil, ErrNoClientTLSConfig
	}
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay")
	logging.ConfigureLogLevel(opts.debug)

	pm, err := pool.NewPeerManager(
		pool.WithPeerServiceAddress(opts.hubbleTarget),
		pool.WithPeerClientBuilder(
			&peerTypes.LocalClientBuilder{
				DialTimeout: opts.dialTimeout,
			},
		),
		pool.WithClientConnBuilder(pool.GRPCClientConnBuilder{
			DialTimeout: opts.dialTimeout,
			Options:     []grpc.DialOption{grpc.WithBlock()},
			TLSConfig:   opts.clientTLSConfig,
		}),
		pool.WithRetryTimeout(opts.retryTimeout),
		pool.WithLogger(logger),
	)
	if err != nil {
		return nil, err
	}
	return &Server{
		pm:   pm,
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

	switch {
	case s.opts.credentials != nil:
		s.server = grpc.NewServer(grpc.Creds(s.opts.credentials))
	case s.opts.insecure:
		s.server = grpc.NewServer()
	default:
		return ErrNoTransportCredentials
	}

	s.pm.Start()
	observerSrv, err := observer.NewServer(s.pm, append(s.opts.observerOptions, observer.WithLogger(s.log))...)
	if err != nil {
		return fmt.Errorf("failed to create observer server: %v", err)
	}

	healthSrv := health.NewServer()
	healthSrv.SetServingStatus(v1.ObserverServiceName, healthpb.HealthCheckResponse_SERVING)

	socket, err := net.Listen("tcp", s.opts.listenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on tcp socket %s: %v", s.opts.listenAddress, err)
	}

	healthpb.RegisterHealthServer(s.server, healthSrv)
	observerpb.RegisterObserverServer(s.server, observerSrv)

	reflection.Register(s.server)
	return s.server.Serve(socket)
}

// Stop terminates the hubble-relay server.
func (s *Server) Stop() {
	s.log.Info("Stopping server...")
	close(s.stop)
	s.server.Stop()
	s.pm.Stop()
	s.log.Info("Server stopped")
}

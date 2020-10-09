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
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/relay/observer"
	"github.com/cilium/cilium/pkg/hubble/relay/pool"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	// ErrNoClientTLSConfig is returned when no client TLS config is set unless
	// WithInsecureClient() is provided.
	ErrNoClientTLSConfig = errors.New("no client TLS config is set")
	// ErrNoServerTLSConfig is returned when no server TLS config is set unless
	// WithInsecureServer() is provided.
	ErrNoServerTLSConfig = errors.New("no server TLS config is set")
)

// Server is a proxy that connects to a running instance of hubble gRPC server
// via unix domain socket.
type Server struct {
	server *grpc.Server
	pm     *pool.PeerManager
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
	if opts.clientTLSConfig == nil && !opts.insecureClient {
		return nil, ErrNoClientTLSConfig
	}
	if opts.serverTLSConfig == nil && !opts.insecureServer {
		return nil, ErrNoServerTLSConfig
	}

	pm, err := pool.NewPeerManager(
		pool.WithPeerServiceAddress(opts.hubbleTarget),
		pool.WithPeerClientBuilder(
			&peerTypes.LocalClientBuilder{
				DialTimeout: opts.dialTimeout,
			},
		),
		pool.WithClientConnBuilder(pool.GRPCClientConnBuilder{
			DialTimeout: opts.dialTimeout,
			Options: []grpc.DialOption{
				grpc.WithBlock(),
				grpc.FailOnNonTempDialError(true),
				// TODO: uncomment the line below once grpc-go is >= v1.30.0
				// currently blocked on v1.29.1, see the following PR for details
				// https://github.com/cilium/cilium/pull/13405
				// grpc.WithReturnConnectionError(),
			},
			TLSConfig: opts.clientTLSConfig,
		}),
		pool.WithRetryTimeout(opts.retryTimeout),
		pool.WithLogger(opts.log),
	)
	if err != nil {
		return nil, err
	}
	return &Server{
		pm:   pm,
		stop: make(chan struct{}),
		opts: opts,
	}, nil
}

// Serve starts the hubble-relay server. Serve does not return unless a
// listening fails with fatal errors. Serve will return a non-nil error if
// Stop() is not called.
func (s *Server) Serve() error {
	s.opts.log.WithField("options", fmt.Sprintf("%+v", s.opts)).Info("Starting server...")

	switch {
	case s.opts.insecureServer:
		s.server = grpc.NewServer()
	case s.opts.serverTLSConfig != nil:
		tlsConfig := s.opts.serverTLSConfig.ServerConfig(&tls.Config{
			MinVersion: MinTLSVersion,
		})
		creds := credentials.NewTLS(tlsConfig)
		s.server = grpc.NewServer(grpc.Creds(creds))
	default:
		return ErrNoServerTLSConfig
	}

	s.pm.Start()
	observerOptions := s.observerOptions()
	observerSrv, err := observer.NewServer(s.pm, observerOptions...)
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
	s.opts.log.Info("Stopping server...")
	close(s.stop)
	s.server.Stop()
	s.pm.Stop()
	s.opts.log.Info("Server stopped")
}

// observerOptions returns the configured hubble-relay observer options along
// with the hubble-relay logger.
func (s *Server) observerOptions() []observer.Option {
	observerOptions := make([]observer.Option, len(s.opts.observerOptions), len(s.opts.observerOptions)+1)
	copy(observerOptions, s.opts.observerOptions)
	observerOptions = append(observerOptions, observer.WithLogger(s.opts.log))
	return observerOptions
}

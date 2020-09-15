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

package server

import (
	"errors"
	"fmt"
	"net"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	errNoListener             = errors.New("no listener configured")
	errNoTransportCredentials = errors.New("no transport credentials configured")
)

// Server is hubble's gRPC server.
type Server struct {
	log  logrus.FieldLogger
	srv  *grpc.Server
	opts serveroption.Options
}

// NewServer creates a new hubble gRPC server.
func NewServer(log logrus.FieldLogger, options ...serveroption.Option) (*Server, error) {
	opts := serveroption.Options{}
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	if opts.Listener == nil {
		return nil, errNoListener
	}
	if opts.TransportCredentials == nil && !opts.Insecure {
		return nil, errNoTransportCredentials
	}
	return &Server{log: log, opts: opts}, nil
}

func (s *Server) newGRPCServer() (*grpc.Server, error) {
	if s.opts.TransportCredentials != nil {
		return grpc.NewServer(grpc.Creds(s.opts.TransportCredentials)), nil
	}
	if s.opts.Insecure {
		return grpc.NewServer(), nil
	}
	return nil, errNoTransportCredentials
}

func (s *Server) initGRPCServer() error {
	srv, err := s.newGRPCServer()
	if err != nil {
		return err
	}
	if s.opts.HealthService != nil {
		healthpb.RegisterHealthServer(srv, s.opts.HealthService)
	}
	if s.opts.ObserverService != nil {
		observerpb.RegisterObserverServer(srv, s.opts.ObserverService)
	}
	if s.opts.PeerService != nil {
		peerpb.RegisterPeerServer(srv, s.opts.PeerService)
	}
	s.srv = srv
	reflection.Register(s.srv)
	return nil
}

// Serve starts the hubble server and accepts new connections on the configured
// listener. Stop should be called to stop the server.
func (s *Server) Serve() error {
	if err := s.initGRPCServer(); err != nil {
		return err
	}
	if s.opts.Listener == nil {
		return errNoListener
	}
	go func(listener net.Listener) {
		if err := s.srv.Serve(s.opts.Listener); err != nil {
			s.log.WithError(err).WithField("address", listener.Addr().String()).Error("Failed to start gRPC server")
		}
	}(s.opts.Listener)
	return nil
}

// Stop stops the hubble server.
func (s *Server) Stop() {
	s.srv.Stop()
}

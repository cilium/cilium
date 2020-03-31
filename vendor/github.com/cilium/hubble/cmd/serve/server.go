// Copyright 2020 Authors of Hubble
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

package serve

import (
	"fmt"
	"net"

	"github.com/cilium/hubble/api/v1/observer"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// Server is hubble's gRPC server.
type Server struct {
	log  *logrus.Entry
	srv  *grpc.Server
	opts Options
}

// NewServer creates a new hubble gRPC server.
func NewServer(log *logrus.Entry, options ...Option) (*Server, error) {
	opts := DefaultOptions
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	return &Server{log: log, opts: opts}, nil
}

func (s *Server) initGRPCServer() {
	srv := grpc.NewServer()
	if s.opts.HealthService != nil {
		healthpb.RegisterHealthServer(srv, s.opts.HealthService)
	}
	if s.opts.ObserverService != nil {
		observer.RegisterObserverServer(srv, *s.opts.ObserverService)
	}
	s.srv = srv
}

// Serve starts the hubble server. It accepts new connections on configured
// listeners. Stop should be called to stop the server.
func (s *Server) Serve() error {
	s.initGRPCServer()
	for name, listener := range s.opts.Listeners {
		go func(name string, listener net.Listener) {
			s.log.WithField("listener", name).Info("Starting gRPC server on listener")
			if err := s.srv.Serve(listener); err != nil {
				s.log.WithError(err).Error("failed to close grpc server")
			}
		}(name, listener)
	}
	return nil
}

// Stop stops the hubble server.
func (s *Server) Stop() {
	s.srv.Stop()
}

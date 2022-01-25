// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Hubble

package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	peerpb "github.com/cilium/cilium/api/v1/peer"
	recorderpb "github.com/cilium/cilium/api/v1/recorder"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
)

var (
	errNoListener        = errors.New("no listener configured")
	errNoServerTLSConfig = errors.New("no server TLS config is set")
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
	if opts.ServerTLSConfig == nil && !opts.Insecure {
		return nil, errNoServerTLSConfig
	}
	return &Server{log: log, opts: opts}, nil
}

func (s *Server) newGRPCServer() (*grpc.Server, error) {
	switch {
	case s.opts.Insecure:
		return grpc.NewServer(), nil
	case s.opts.ServerTLSConfig != nil:
		tlsConfig := s.opts.ServerTLSConfig.ServerConfig(&tls.Config{
			MinVersion: serveroption.MinTLSVersion,
		})
		creds := credentials.NewTLS(tlsConfig)
		return grpc.NewServer(grpc.Creds(creds)), nil
	default:
		return nil, errNoServerTLSConfig
	}
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
	if s.opts.RecorderService != nil {
		recorderpb.RegisterRecorderServer(srv, s.opts.RecorderService)
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

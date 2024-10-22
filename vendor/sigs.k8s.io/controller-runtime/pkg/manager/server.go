/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package manager

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	crlog "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	_ Runnable               = (*Server)(nil)
	_ LeaderElectionRunnable = (*Server)(nil)
)

// Server is a general purpose HTTP server Runnable for a manager.
// It is used to serve some internal handlers for health probes and profiling,
// but it can also be used to run custom servers.
type Server struct {
	// Name is an optional string that describes the purpose of the server. It is used in logs to distinguish
	// among multiple servers.
	Name string

	// Server is the HTTP server to run. It is required.
	Server *http.Server

	// Listener is an optional listener to use. If not set, the server start a listener using the server.Addr.
	// Using a listener is useful when the port reservation needs to happen in advance of this runnable starting.
	Listener net.Listener

	// OnlyServeWhenLeader is an optional bool that indicates that the server should only be started when the manager is the leader.
	OnlyServeWhenLeader bool

	// ShutdownTimeout is an optional duration that indicates how long to wait for the server to shutdown gracefully. If not set,
	// the server will wait indefinitely for all connections to close.
	ShutdownTimeout *time.Duration
}

// Start starts the server. It will block until the server is stopped or an error occurs.
func (s *Server) Start(ctx context.Context) error {
	log := crlog.FromContext(ctx)
	if s.Name != "" {
		log = log.WithValues("name", s.Name)
	}
	log = log.WithValues("addr", s.addr())

	serverShutdown := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Info("shutting down server")

		shutdownCtx := context.Background()
		if s.ShutdownTimeout != nil {
			var shutdownCancel context.CancelFunc
			shutdownCtx, shutdownCancel = context.WithTimeout(context.Background(), *s.ShutdownTimeout)
			defer shutdownCancel()
		}

		if err := s.Server.Shutdown(shutdownCtx); err != nil {
			log.Error(err, "error shutting down server")
		}
		close(serverShutdown)
	}()

	log.Info("starting server")
	if err := s.serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	<-serverShutdown
	return nil
}

// NeedLeaderElection returns true if the server should only be started when the manager is the leader.
func (s *Server) NeedLeaderElection() bool {
	return s.OnlyServeWhenLeader
}

func (s *Server) addr() string {
	if s.Listener != nil {
		return s.Listener.Addr().String()
	}
	return s.Server.Addr
}

func (s *Server) serve() error {
	if s.Listener != nil {
		return s.Server.Serve(s.Listener)
	}
	return s.Server.ListenAndServe()
}

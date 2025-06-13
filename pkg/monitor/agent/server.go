// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// buildServer opens a listener socket at path. It exits with logging on all
// errors.
func buildServer(logger *slog.Logger, path string) (*net.UnixListener, error) {
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve unix address %s: %w", path, err)
	}
	os.Remove(path)
	server, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on unix socket %s: %w", path, err)
	}

	if os.Getuid() == 0 {
		err := api.SetDefaultPermissions(logger.Debug, path)
		if err != nil {
			server.Close()
			return nil, fmt.Errorf("cannot set default permissions on socket %s: %w", path, err)
		}
	}

	return server, nil
}

// server serves the Cilium monitor API on the unix domain socket
type server struct {
	logger   *slog.Logger
	listener net.Listener
	monitor  Agent
}

// ServeMonitorAPI serves the Cilium 1.2 monitor API on a unix domain socket.
// This method starts the server in the background. The server is stopped when
// ctx is cancelled. Each incoming connection registers a new listener on
// monitor.
func ServeMonitorAPI(ctx context.Context, logger *slog.Logger, monitor Agent, queueSize int) error {
	listener, err := buildServer(logger, defaults.MonitorSockPath1_2)
	if err != nil {
		return err
	}

	s := &server{
		listener: listener,
		monitor:  monitor,
		logger:   logger,
	}

	logger.Info(fmt.Sprintf("Serving cilium node monitor v1.2 API at unix://%s", defaults.MonitorSockPath1_2))

	go s.connectionHandler1_2(ctx, queueSize)

	return nil
}

// connectionHandler1_2 handles all the incoming connections and sets up the
// listener objects. It will block until ctx is cancelled.
func (s *server) connectionHandler1_2(ctx context.Context, queueSize int) {
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for !isCtxDone(ctx) {
		conn, err := s.listener.Accept()
		switch {
		case isCtxDone(ctx):
			if conn != nil {
				conn.Close()
			}
			return
		case err != nil:
			s.logger.Warn("Error accepting connection", logfields.Error, err)
			continue
		}

		newListener := newListenerv1_2(s.logger, conn, queueSize, s.monitor.RemoveListener)
		s.monitor.RegisterNewListener(newListener)
	}
}

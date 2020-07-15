// Copyright 2017-2019 Authors of Cilium
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

package agent

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "monitor-agent")
)

// buildServer opens a listener socket at path. It exits with logging on all
// errors.
func buildServer(path string) (net.Listener, error) {
	os.Remove(path)
	server, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on unix socket %s: %s", path, err)
	}

	if os.Getuid() == 0 {
		err := api.SetDefaultPermissions(path)
		if err != nil {
			return nil, fmt.Errorf("cannot set default permissions on socket %s: %s", path, err)
		}
	}

	return server, nil
}

// server serves the Cilium monitor API on the unix domain socket
type server struct {
	listener net.Listener
	monitor  *Agent
}

// ServeMonitorAPI serves the Cilium 1.2 monitor API on a unix domain socket.
// This method starts the server in the background. The server is stopped when
// monitor.Context() is cancelled. Each incoming connection registers a new
// listener on monitor.
func ServeMonitorAPI(monitor *Agent) error {
	listener, err := buildServer(defaults.MonitorSockPath1_2)
	if err != nil {
		return err
	}

	s := &server{
		listener: listener,
		monitor:  monitor,
	}

	log.Infof("Serving cilium node monitor v1.2 API at unix://%s", defaults.MonitorSockPath1_2)

	go s.connectionHandler1_2(monitor.Context())

	return nil
}

// connectionHandler1_2 handles all the incoming connections and sets up the
// listener objects. It will block until ctx is cancelled.
func (s *server) connectionHandler1_2(ctx context.Context) {
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
			log.WithError(err).Warn("Error accepting connection")
			continue
		}

		newListener := newListenerv1_2(conn, option.Config.MonitorQueueSize, s.monitor.RemoveListener)
		s.monitor.RegisterNewListener(newListener)
	}
}

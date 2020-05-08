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

package serveroption

import (
	"fmt"
	"net"
	"os"
	"strings"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/api"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// Options stores all the configuration values for the hubble server.
type Options struct {
	TCPListener        net.Listener
	UnixSocketListener net.Listener
	HealthService      healthpb.HealthServer
	ObserverService    observerpb.ObserverServer
	PeerService        peerpb.PeerServer
}

// Option customizes then configuration of the hubble server.
type Option func(o *Options) error

// WithTCPListener configures a TCP listener with the address.
func WithTCPListener(address string) Option {
	return func(o *Options) error {
		socket, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		if o.TCPListener != nil {
			socket.Close()
			return fmt.Errorf("listener already configured: %s", address)
		}
		o.TCPListener = socket
		return nil
	}
}

// WithUnixSocketListener configures a unix domain socket listener with the
// given file path. When the process runs in privileged mode, the file group
// owner is set to socketGroup.
func WithUnixSocketListener(path string) Option {
	return func(o *Options) error {
		socketPath := strings.TrimPrefix(path, "unix://")
		unix.Unlink(socketPath)
		socket, err := net.Listen("unix", socketPath)
		if err != nil {
			return err
		}
		if os.Getuid() == 0 {
			if err := api.SetDefaultPermissions(socketPath); err != nil {
				return err
			}
		}
		if o.UnixSocketListener != nil {
			socket.Close()
			unix.Unlink(socketPath)
			return fmt.Errorf("listener already configured: %s", path)
		}
		o.UnixSocketListener = socket
		return nil
	}
}

// WithHealthService configures the server to expose the gRPC health service.
func WithHealthService() Option {
	return func(o *Options) error {
		healthSvc := health.NewServer()
		healthSvc.SetServingStatus(v1.ObserverServiceName, healthpb.HealthCheckResponse_SERVING)
		o.HealthService = healthSvc
		return nil
	}
}

// WithObserverService configures the server to expose the given observer server service.
func WithObserverService(svc observerpb.ObserverServer) Option {
	return func(o *Options) error {
		o.ObserverService = svc
		return nil
	}
}

// WithPeerService configures the server to expose the given peer server service.
func WithPeerService(svc peerpb.PeerServer) Option {
	return func(o *Options) error {
		o.PeerService = svc
		return nil
	}
}

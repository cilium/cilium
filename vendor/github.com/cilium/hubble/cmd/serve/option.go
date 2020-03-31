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
	"os"
	"strings"

	"github.com/cilium/hubble/pkg/api"
	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/server"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// DefaultOptions is the reference point for default values.
var DefaultOptions = Options{
	Listeners: make(map[string]net.Listener),
}

// Options stores all the configuration values for the hubble server.
type Options struct {
	Listeners       map[string]net.Listener
	HealthService   *health.Server
	ObserverService *server.GRPCServer
}

// Option customizes then configuration of the hubble server.
type Option func(o *Options) error

// WithListeners configures listeners. Addresses that are prefixed with
// 'unix://' are assumed to be UNIX domain sockets, in which case appropriate
// permissions are tentatively set and the group owner is set to socketGroup.
// Otherwise, the address is assumed to be TCP.
func WithListeners(addresses []string, socketGroup string) Option {
	return func(o *Options) error {
		var opt Option
		for _, address := range addresses {
			if strings.HasPrefix(address, "unix://") {
				opt = WithUnixSocketListener(address, socketGroup)
			} else {
				opt = WithTCPListener(address)
			}
			if err := opt(o); err != nil {
				for _, l := range o.Listeners {
					l.Close()
				}
				return err
			}
		}
		return nil
	}
}

// WithTCPListener configures a TCP listener with the address.
func WithTCPListener(address string) Option {
	return func(o *Options) error {
		socket, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		if _, exist := o.Listeners[address]; exist {
			socket.Close()
			return fmt.Errorf("listener already configured: %s", address)
		}
		o.Listeners[address] = socket
		return nil
	}
}

// WithUnixSocketListener configures a unix domain socket listener with the
// given file path. When the process runs in privileged mode, the file group
// owner is set to socketGroup.
func WithUnixSocketListener(path string, socketGroup string) Option {
	return func(o *Options) error {
		socketPath := strings.TrimPrefix(path, "unix://")
		unix.Unlink(socketPath)
		socket, err := net.Listen("unix", socketPath)
		if err != nil {
			return err
		}
		if os.Getuid() == 0 {
			if err := api.SetDefaultPermissions(socketPath, socketGroup); err != nil {
				return err
			}
		}
		if _, exist := o.Listeners[path]; exist {
			socket.Close()
			unix.Unlink(socketPath)
			return fmt.Errorf("listener already configured: %s", path)
		}
		o.Listeners[path] = socket
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
func WithObserverService(svc server.GRPCServer) Option {
	return func(o *Options) error {
		o.ObserverService = &svc
		return nil
	}
}

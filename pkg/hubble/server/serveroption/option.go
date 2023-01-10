// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Copyright Authors of Cilium

package serveroption

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	peerpb "github.com/cilium/cilium/api/v1/peer"
	recorderpb "github.com/cilium/cilium/api/v1/recorder"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

// MinTLSVersion defines the minimum TLS version clients are expected to
// support in order to establish a connection to the hubble server.
const MinTLSVersion = tls.VersionTLS13

// Options stores all the configuration values for the hubble server.
type Options struct {
	Listener               net.Listener
	HealthService          healthpb.HealthServer
	ObserverService        observerpb.ObserverServer
	PeerService            peerpb.PeerServer
	RecorderService        recorderpb.RecorderServer
	ServerTLSConfig        certloader.ServerConfigBuilder
	Insecure               bool
	GRPCMetrics            *grpc_prometheus.ServerMetrics
	GRPCUnaryInterceptors  []grpc.UnaryServerInterceptor
	GRPCStreamInterceptors []grpc.StreamServerInterceptor
}

// Option customizes the hubble server's configuration.
type Option func(o *Options) error

// WithTCPListener configures a TCP listener with the address.
func WithTCPListener(address string) Option {
	return func(o *Options) error {
		socket, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		if o.Listener != nil {
			socket.Close()
			return fmt.Errorf("listener already configured: %s", address)
		}
		o.Listener = socket
		return nil
	}
}

// WithUnixSocketListener configures a unix domain socket listener with the
// given file path. When the process runs in privileged mode, the file group
// owner is set to socketGroup.
func WithUnixSocketListener(path string) Option {
	return func(o *Options) error {
		if o.Listener != nil {
			return fmt.Errorf("listener already configured")
		}
		socketPath := strings.TrimPrefix(path, "unix://")
		unix.Unlink(socketPath)
		socket, err := net.Listen("unix", socketPath)
		if err != nil {
			return err
		}
		if os.Getuid() == 0 {
			if err := api.SetDefaultPermissions(socketPath); err != nil {
				socket.Close()
				return err
			}
		}
		o.Listener = socket
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

// WithInsecure disables transport security. Transport security is required
// unless WithInsecure is set. Use WithTLS to set transport credentials for
// transport security.
func WithInsecure() Option {
	return func(o *Options) error {
		o.Insecure = true
		return nil
	}
}

// WithServerTLS sets the transport credentials for the server based on TLS.
func WithServerTLS(cfg certloader.ServerConfigBuilder) Option {
	return func(o *Options) error {
		o.ServerTLSConfig = cfg
		return nil
	}
}

// WithRecorderService configures the server to expose the given recorder
// server service.
func WithRecorderService(svc recorderpb.RecorderServer) Option {
	return func(o *Options) error {
		o.RecorderService = svc
		return nil
	}
}

// WithGRPCMetrics configures the server with the specified prometheus gPRC
// ServerMetrics.
func WithGRPCMetrics(grpcMetrics *grpc_prometheus.ServerMetrics) Option {
	return func(o *Options) error {
		o.GRPCMetrics = grpcMetrics
		return nil
	}
}

// WithGRPCStreamInterceptor configures the server with the given gRPC server stream interceptors
func WithGRPCStreamInterceptor(interceptors ...grpc.StreamServerInterceptor) Option {
	return func(o *Options) error {
		o.GRPCStreamInterceptors = append(o.GRPCStreamInterceptors, interceptors...)
		return nil
	}
}

// WithGRPCUnaryInterceptor configures the server with the given gRPC server stream interceptors
func WithGRPCUnaryInterceptor(interceptors ...grpc.UnaryServerInterceptor) Option {
	return func(o *Options) error {
		o.GRPCUnaryInterceptors = append(o.GRPCUnaryInterceptors, interceptors...)
		return nil
	}
}

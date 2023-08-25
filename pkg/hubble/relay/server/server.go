// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/peer"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/hubble/relay/observer"
	"github.com/cilium/cilium/pkg/hubble/relay/pool"
)

var (
	// ErrNoClientTLSConfig is returned when no client TLS config is set unless
	// WithInsecureClient() is provided.
	ErrNoClientTLSConfig = errors.New("no client TLS config is set")
	// ErrNoServerTLSConfig is returned when no server TLS config is set unless
	// WithInsecureServer() is provided.
	ErrNoServerTLSConfig = errors.New("no server TLS config is set")

	registry = prometheus.NewPedanticRegistry()
)

func init() {
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(collectors.NewGoCollector())
}

// Server is a proxy that connects to a running instance of hubble gRPC server
// via unix domain socket.
type Server struct {
	server        *grpc.Server
	pm            *pool.PeerManager
	healthServer  *health.Server
	metricsServer *http.Server
	opts          options
	stop          chan struct{}
}

// New creates a new Server.
func New(options ...Option) (*Server, error) {
	opts := defaultOptions // start with defaults
	options = append(options, DefaultOptions...)
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

	var peerClientBuilder peerTypes.ClientBuilder = &peerTypes.LocalClientBuilder{
		DialTimeout: opts.dialTimeout,
	}
	if !strings.HasPrefix(opts.peerTarget, "unix://") {
		peerClientBuilder = &peerTypes.RemoteClientBuilder{
			DialTimeout:   opts.dialTimeout,
			TLSConfig:     opts.clientTLSConfig,
			TLSServerName: peer.TLSServerName(defaults.PeerServiceName, opts.clusterName),
		}
	}

	pm, err := pool.NewPeerManager(
		pool.WithPeerServiceAddress(opts.peerTarget),
		pool.WithPeerClientBuilder(peerClientBuilder),
		pool.WithClientConnBuilder(pool.GRPCClientConnBuilder{
			DialTimeout: opts.dialTimeout,
			Options: []grpc.DialOption{
				grpc.WithBlock(),
				grpc.FailOnNonTempDialError(true),
				grpc.WithReturnConnectionError(),
			},
			TLSConfig: opts.clientTLSConfig,
		}),
		pool.WithRetryTimeout(opts.retryTimeout),
		pool.WithLogger(opts.log),
	)
	if err != nil {
		return nil, err
	}

	var serverOpts []grpc.ServerOption

	for _, interceptor := range opts.grpcUnaryInterceptors {
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(interceptor))
	}
	for _, interceptor := range opts.grpcStreamInterceptors {
		serverOpts = append(serverOpts, grpc.StreamInterceptor(interceptor))
	}

	if opts.serverTLSConfig != nil {
		tlsConfig := opts.serverTLSConfig.ServerConfig(&tls.Config{
			MinVersion: MinTLSVersion,
		})
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	grpcServer := grpc.NewServer(serverOpts...)

	observerOptions := copyObserverOptionsWithLogger(opts.log, opts.observerOptions)
	observerSrv, err := observer.NewServer(pm, observerOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create observer server: %v", err)
	}
	healthSrv := health.NewServer()

	observerpb.RegisterObserverServer(grpcServer, observerSrv)
	healthpb.RegisterHealthServer(grpcServer, healthSrv)
	reflection.Register(grpcServer)

	if opts.grpcMetrics != nil {
		registry.MustRegister(opts.grpcMetrics)
		opts.grpcMetrics.InitializeMetrics(grpcServer)
	}

	var metricsServer *http.Server
	if opts.metricsListenAddress != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		metricsServer = &http.Server{
			Addr:    opts.metricsListenAddress,
			Handler: mux,
		}
	}

	return &Server{
		pm:            pm,
		stop:          make(chan struct{}),
		server:        grpcServer,
		metricsServer: metricsServer,
		healthServer:  healthSrv,
		opts:          opts,
	}, nil
}

// Serve starts the hubble-relay server. Serve does not return unless a
// listening fails with fatal errors. Serve will return a non-nil error if
// Stop() is not called.
func (s *Server) Serve() error {
	var eg errgroup.Group
	if s.metricsServer != nil {
		eg.Go(func() error {
			s.opts.log.WithField("address", s.opts.metricsListenAddress).Info("Starting metrics server...")
			return s.metricsServer.ListenAndServe()
		})
	}

	eg.Go(func() error {
		s.opts.log.WithField("options", fmt.Sprintf("%+v", s.opts)).Info("Starting gRPC server...")
		s.pm.Start()
		socket, err := net.Listen("tcp", s.opts.listenAddress)
		if err != nil {
			return fmt.Errorf("failed to listen on tcp socket %s: %v", s.opts.listenAddress, err)
		}

		s.healthServer.SetServingStatus(v1.ObserverServiceName, healthpb.HealthCheckResponse_SERVING)
		return s.server.Serve(socket)
	})

	return eg.Wait()
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
func copyObserverOptionsWithLogger(log logrus.FieldLogger, options []observer.Option) []observer.Option {
	newOptions := make([]observer.Option, len(options), len(options)+1)
	copy(newOptions, options)
	newOptions = append(newOptions, observer.WithLogger(log))
	return newOptions
}

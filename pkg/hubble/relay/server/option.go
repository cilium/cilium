// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"crypto/tls"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/hubble/relay/observer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// MinTLSVersion defines the minimum TLS version clients are expected to
// support in order to establish a connection to the hubble-relay server.
const MinTLSVersion = tls.VersionTLS13

// options stores all the configuration values for the hubble-relay server.
type options struct {
	peerTarget             string
	dialTimeout            time.Duration
	retryTimeout           time.Duration
	listenAddress          string
	metricsListenAddress   string
	log                    logrus.FieldLogger
	serverTLSConfig        certloader.ServerConfigBuilder
	insecureServer         bool
	clientTLSConfig        certloader.ClientConfigBuilder
	clusterName            string
	insecureClient         bool
	observerOptions        []observer.Option
	grpcMetrics            *grpc_prometheus.ServerMetrics
	grpcUnaryInterceptors  []grpc.UnaryServerInterceptor
	grpcStreamInterceptors []grpc.StreamServerInterceptor
}

// defaultOptions is the reference point for default values.
var defaultOptions = options{
	peerTarget:    defaults.PeerTarget,
	dialTimeout:   defaults.DialTimeout,
	retryTimeout:  defaults.RetryTimeout,
	listenAddress: defaults.ListenAddress,
	log:           logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay"),
}

// DefaultOptions to include in the server. Other packages may extend this
// in their init() function.
var DefaultOptions []Option

// Option customizes the configuration of the hubble-relay server.
type Option func(o *options) error

// WithPeerTarget sets the URL of the hubble peer service to connect to.
func WithPeerTarget(t string) Option {
	return func(o *options) error {
		o.peerTarget = t
		return nil
	}
}

// WithDialTimeout sets the dial timeout that is used when establishing a
// connection to a hubble peer.
func WithDialTimeout(t time.Duration) Option {
	return func(o *options) error {
		o.dialTimeout = t
		return nil
	}
}

// WithRetryTimeout sets the duration to wait before attempting to re-connect
// to a hubble peer when the connection is lost.
func WithRetryTimeout(t time.Duration) Option {
	return func(o *options) error {
		o.retryTimeout = t
		return nil
	}
}

// WithListenAddress sets the listen address for the hubble-relay server.
func WithListenAddress(a string) Option {
	return func(o *options) error {
		o.listenAddress = a
		return nil
	}
}

// WithMetricsListenAddress sets the listen address for the hubble-relay server.
func WithMetricsListenAddress(a string) Option {
	return func(o *options) error {
		o.metricsListenAddress = a
		return nil
	}
}

// WithSortBufferMaxLen sets the maximum number of flows that can be buffered
// for sorting before being sent to the client. The provided value must be
// greater than 0 and is to be understood per client request. Therefore, it is
// advised to keep the value moderate (a value between 30 and 100 should
// constitute a good choice in most cases).
func WithSortBufferMaxLen(i int) Option {
	return func(o *options) error {
		o.observerOptions = append(o.observerOptions, observer.WithSortBufferMaxLen(i))
		return nil
	}
}

// WithSortBufferDrainTimeout sets the sort buffer drain timeout value. For
// flows requests where the total number of flows cannot be determined
// (typically for flows requests in follow mode), a flow is taken out of the
// buffer and sent to the client after duration d if the buffer is not full.
// This value must be greater than 0. Setting this value too low would render
// the flows sorting operation ineffective. A value between 500 milliseconds
// and 3 seconds should be constitute a good choice in most cases.
func WithSortBufferDrainTimeout(d time.Duration) Option {
	return func(o *options) error {
		o.observerOptions = append(o.observerOptions, observer.WithSortBufferDrainTimeout(d))
		return nil
	}
}

// WithErrorAggregationWindow sets a time window during which errors with the
// same error message are coalesced. The aggregated error is forwarded to the
// downstream consumer either when the window expires or when a new, different
// error occurs (whichever happens first)
func WithErrorAggregationWindow(d time.Duration) Option {
	return func(o *options) error {
		o.observerOptions = append(o.observerOptions, observer.WithErrorAggregationWindow(d))
		return nil
	}
}

// WithLogger set the logger used by hubble-relay.
func WithLogger(log logrus.FieldLogger) Option {
	return func(o *options) error {
		o.log = log
		return nil
	}
}

// WithServerTLS sets the transport credentials for the server based on TLS.
func WithServerTLS(cfg certloader.ServerConfigBuilder) Option {
	return func(o *options) error {
		o.serverTLSConfig = cfg
		return nil
	}
}

// WithInsecureServer disables transport security. Transport security is
// required for the server unless WithInsecureServer is set (not recommended).
func WithInsecureServer() Option {
	return func(o *options) error {
		o.insecureServer = true
		return nil
	}
}

// WithClientTLS sets the transport credentials for connecting to peers based
// on the provided TLS configuration.
func WithClientTLS(cfg certloader.ClientConfigBuilder) Option {
	return func(o *options) error {
		o.clientTLSConfig = cfg
		return nil
	}
}

// WithInsecureClient disables transport security for connection to Hubble
// server instances. Transport security is required to WithInsecureClient is
// set (not recommended).
func WithInsecureClient() Option {
	return func(o *options) error {
		o.insecureClient = true
		return nil
	}
}

// WithLocalClusterName sets the cluster name for the peer service
// so that it knows how to construct the proper TLSServerName
// to validate mTLS in the K8s Peer service.
func WithLocalClusterName(clusterName string) Option {
	return func(o *options) error {
		o.clusterName = clusterName
		return nil
	}
}

// WithGRPCMetrics configures the server with the specified prometheus gPRC
// ServerMetrics.
func WithGRPCMetrics(grpcMetrics *grpc_prometheus.ServerMetrics) Option {
	return func(o *options) error {
		o.grpcMetrics = grpcMetrics
		return nil
	}
}

// WithGRPCStreamInterceptor configures the server with the given gRPC server stream interceptors
func WithGRPCStreamInterceptor(interceptors ...grpc.StreamServerInterceptor) Option {
	return func(o *options) error {
		o.grpcStreamInterceptors = append(o.grpcStreamInterceptors, interceptors...)
		return nil
	}
}

// WithGRPCUnaryInterceptor configures the server with the given gRPC server stream interceptors
func WithGRPCUnaryInterceptor(interceptors ...grpc.UnaryServerInterceptor) Option {
	return func(o *options) error {
		o.grpcUnaryInterceptors = append(o.grpcUnaryInterceptors, interceptors...)
		return nil
	}
}

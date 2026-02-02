// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/ztunnel/table"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// xdsTypeURLAddress is the Aggregated Discovery Service (ADS) type URL
	// signaling a subscription to workload and services.
	xdsTypeURLAddress = "type.googleapis.com/istio.workload.Address"
	// xdsTypeURLAuthorization is the type URL signaling a subscription to
	// authorization policies.
	xdsTypeURLAuthorization = "type.googleapis.com/istio.security.Authorization"
)

var _ v3.AggregatedDiscoveryServiceServer = (*Server)(nil)

// Server is a private implemenation of xDS for use with the stand-alone
// zTunnel proxy.
//
// This xDS server implements a scoped-down xDS API capable of sending
// workload and service events to zTunnel.
type Server struct {
	l                         net.Listener
	g                         *grpc.Server
	log                       *slog.Logger
	k8sCiliumEndpointsWatcher *watchers.K8sCiliumEndpointsWatcher
	db                        *statedb.DB
	enrolledNamespaceTable    statedb.RWTable[*table.EnrolledNamespace]
	endpointEventChan         chan *EndpointEvent
	metrics                   *Metrics
	// xdsUnixAddr is the unix socket path for the XDS server.
	xdsUnixAddr string
	v3.UnimplementedAggregatedDiscoveryServiceServer
}

func newServer(
	log *slog.Logger,
	db *statedb.DB,
	k8sCiliumEndpointsWatcher *watchers.K8sCiliumEndpointsWatcher,
	enrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace],
	xdsUnixAddr string,
	metrics *Metrics,
) *Server {
	return &Server{
		log:                       log,
		k8sCiliumEndpointsWatcher: k8sCiliumEndpointsWatcher,
		endpointEventChan:         make(chan *EndpointEvent, 1024),
		db:                        db,
		enrolledNamespaceTable:    enrolledNamespaceTable,
		xdsUnixAddr:               xdsUnixAddr,
		metrics:                   metrics,
	}
}

// Serve will create the listening gRPC service and register the required xDS
// endpoints.
//
// If Serve returns without an error the gRPC server is launched within a new
// go routine.
//
// Server.GracefulStop() can be used to kill the running gRPC server.
func (x *Server) Serve() error {
	var err error

	// keepalive options match config values from:
	// https://github.com/istio/istio/blob/b68cd04f9f132c1361d62eb14125e915e8011428/pkg/keepalive/options.go#L45
	// Without these, our grpc server will eventually send a Go Away message to ztunnel, killing the connection.
	grpcOptions := []grpc.ServerOption{
		// No TLS credentials needed for Unix Domain Sockets as they are local
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: 15 * time.Second,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:                  30 * time.Second,
			Timeout:               10 * time.Second,
			MaxConnectionAge:      time.Duration(math.MaxInt64), // INFINITY
			MaxConnectionAgeGrace: 10 * time.Second,
		}),
	}

	x.g = grpc.NewServer(grpcOptions...)
	v3.RegisterAggregatedDiscoveryServiceServer(x.g, x)

	// Remove existing socket file if it exists to avoid "address already in use" errors
	if err = os.Remove(x.xdsUnixAddr); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing unix socket %s: %w", x.xdsUnixAddr, err)
	}

	x.l, err = net.Listen("unix", x.xdsUnixAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", x.xdsUnixAddr, err)
	}

	x.log.Info("zTunnel xDS server started", "socket", x.xdsUnixAddr)
	go func() {
		if err = x.g.Serve(x.l); err != nil {
			x.log.Error("gRPC server error", logfields.Error, err)
		}
	}()
	return nil
}

// GracefulStop halts the server gracefully, returning a nil error from the
// underlying gRPC server.
//
// This is useful to kill the server without producing a conflated error that
// would occur when net.Listen() returns an error.
func (x *Server) GracefulStop() {
	x.g.GracefulStop()
}

func (x *Server) StreamAggregatedResources(stream v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	x.log.Debug("received StreamAggregatedResources request")
	return fmt.Errorf("unimplemented")
}

// DeltaAggregatedResources is a bidi stream initialization method. zTunnel
// receives Workload, Service, and Authorization policy events via this stream.
//
// This handler runs in its own goroutine.
//
// When zTunnel connects to our xDS server this method is invoked to initialize
// a gRPC stream. The method's lifespan is directly tied to the gRPC stream and
// the stream will close when this method returns.
//
// We create a StreamProcessor structure to handle the interaction between
// Cilium and the zTunnel proxy.
func (x *Server) DeltaAggregatedResources(stream v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	x.log.Debug("received DeltaAggregatedResources request")

	// check out stream context, just incase the client immediately closed it,
	// we won't do any work in that case.
	if stream.Context().Err() != nil {
		x.log.Info("stream context immediately canceld, aborting stream initialization")
		return stream.Context().Err()
	}

	params := StreamProcessorParams{
		Stream:                    stream,
		StreamRecv:                make(chan *v3.DeltaDiscoveryRequest, 1),
		EndpointEventRecv:         x.endpointEventChan,
		K8sCiliumEndpointsWatcher: x.k8sCiliumEndpointsWatcher,
		Log:                       x.log,
		EnrolledNamespaceTable:    x.enrolledNamespaceTable,
		DB:                        x.db,
		Metrics:                   x.metrics,
	}

	x.log.Debug("begin processing DeltaAggregatedResources stream")
	sp := NewStreamProcessor(&params)
	// blocks until stream's context is killed.
	sp.Start()

	return stream.Context().Err()
}

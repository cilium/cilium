// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"net"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_service_cluster "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_service_endpoint "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	envoy_service_listener "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	envoy_service_route "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	envoy_service_secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ErrNotImplemented is the error returned by gRPC methods that are not
// implemented by Cilium.
var ErrNotImplemented = errors.New("not implemented")

// startXDSGRPCServer starts a gRPC server to serve xDS APIs using the given
// resource watcher and network listener.
// Returns a function that stops the GRPC server when called.
func (s *xdsServer) startXDSGRPCServer(listener net.Listener, config map[string]*xds.ResourceTypeConfiguration) context.CancelFunc {
	grpcServer := grpc.NewServer()

	// xdsServer optionally pauses serving any resources until endpoints have been restored
	xdsServer := xds.NewServer(s.logger, config, s.restorerPromise, s.config.metrics)
	dsServer := (*xdsGRPCServer)(xdsServer)

	// TODO: https://github.com/cilium/cilium/issues/5051
	// Implement IncrementalAggregatedResources to support Incremental xDS.
	// envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_secret.RegisterSecretDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_endpoint.RegisterEndpointDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_cluster.RegisterClusterDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_route.RegisterRouteDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_listener.RegisterListenerDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterNetworkPolicyDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterNetworkPolicyHostsDiscoveryServiceServer(grpcServer, dsServer)

	reflection.Register(grpcServer)

	ctx, cancel := context.WithTimeout(context.Background(), s.config.policyRestoreTimeout)
	go func() {
		if s.restorerPromise != nil {
			s.logger.Info("Envoy: Waiting for endpoint restorer before serving xDS resources...")
			restorer, err := s.restorerPromise.Await(ctx)
			if err == nil && restorer != nil {
				s.logger.Info("Envoy: Waiting for endpoint restoration before serving xDS resources...")
				err = restorer.WaitForInitialPolicy(ctx)
			}
			if errors.Is(err, context.Canceled) {
				s.logger.Debug("Envoy: xDS server stopped before started serving")
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				s.logger.Warn("Envoy: Endpoint policy restoration took longer than configured restore timeout, starting serving resources to Envoy",
					logfields.Duration, s.config.policyRestoreTimeout,
				)
			}
			// Tell xdsServer it's time to start waiting for acknowledgements
			xdsServer.RestoreCompleted()
		}

		s.logger.Info("Envoy: Starting xDS gRPC server listening",
			logfields.Address, listener.Addr(),
		)
		if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			s.logger.Error("Envoy: Failed to serve xDS gRPC API",
				logfields.Error, err,
			)
		}
	}()

	return func() {
		cancel()
		grpcServer.Stop()
	}
}

// xdsGRPCServer handles gRPC streaming discovery requests for the
// resource types supported by Cilium.
type xdsGRPCServer xds.Server

// TODO: https://github.com/cilium/cilium/issues/5051
// Implement IncrementalAggregatedResources also to support Incremental xDS.
// func (s *xdsGRPCServer) StreamAggregatedResources(stream envoy_service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
//	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, xds.AnyTypeURL)
// }

func (s *xdsGRPCServer) DeltaListeners(stream envoy_service_listener.ListenerDiscoveryService_DeltaListenersServer) error {
	return ErrNotImplemented
}

func (s *xdsGRPCServer) StreamListeners(stream envoy_service_listener.ListenerDiscoveryService_StreamListenersServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, ListenerTypeURL)
}

func (s *xdsGRPCServer) FetchListeners(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) DeltaRoutes(stream envoy_service_route.RouteDiscoveryService_DeltaRoutesServer) error {
	return ErrNotImplemented
}

func (s *xdsGRPCServer) StreamRoutes(stream envoy_service_route.RouteDiscoveryService_StreamRoutesServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, RouteTypeURL)
}

func (s *xdsGRPCServer) FetchRoutes(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) DeltaClusters(stream envoy_service_cluster.ClusterDiscoveryService_DeltaClustersServer) error {
	return ErrNotImplemented
}

func (s *xdsGRPCServer) StreamClusters(stream envoy_service_cluster.ClusterDiscoveryService_StreamClustersServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, ClusterTypeURL)
}

func (s *xdsGRPCServer) FetchClusters(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) DeltaEndpoints(stream envoy_service_endpoint.EndpointDiscoveryService_DeltaEndpointsServer) error {
	return ErrNotImplemented
}

func (s *xdsGRPCServer) StreamEndpoints(stream envoy_service_endpoint.EndpointDiscoveryService_StreamEndpointsServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, EndpointTypeURL)
}

func (s *xdsGRPCServer) FetchEndpoints(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) DeltaSecrets(stream envoy_service_secret.SecretDiscoveryService_DeltaSecretsServer) error {
	return ErrNotImplemented
}

func (s *xdsGRPCServer) StreamSecrets(stream envoy_service_secret.SecretDiscoveryService_StreamSecretsServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, SecretTypeURL)
}

func (s *xdsGRPCServer) FetchSecrets(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamNetworkPolicies(stream cilium.NetworkPolicyDiscoveryService_StreamNetworkPoliciesServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, NetworkPolicyTypeURL)
}

func (s *xdsGRPCServer) FetchNetworkPolicies(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamNetworkPolicyHosts(stream cilium.NetworkPolicyHostsDiscoveryService_StreamNetworkPolicyHostsServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, NetworkPolicyHostsTypeURL)
}

func (s *xdsGRPCServer) FetchNetworkPolicyHosts(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

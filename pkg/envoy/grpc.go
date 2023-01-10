// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"net"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_service_cluster "github.com/cilium/proxy/go/envoy/service/cluster/v3"
	envoy_service_discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	envoy_service_endpoint "github.com/cilium/proxy/go/envoy/service/endpoint/v3"
	envoy_service_listener "github.com/cilium/proxy/go/envoy/service/listener/v3"
	envoy_service_route "github.com/cilium/proxy/go/envoy/service/route/v3"
	envoy_service_secret "github.com/cilium/proxy/go/envoy/service/secret/v3"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

var (
	// ErrNotImplemented is the error returned by gRPC methods that are not
	// implemented by Cilium.
	ErrNotImplemented = errors.New("not implemented")
)

// startXDSGRPCServer starts a gRPC server to serve xDS APIs using the given
// resource watcher and network listener.
// Returns a function that stops the GRPC server when called.
func startXDSGRPCServer(listener net.Listener, config map[string]*xds.ResourceTypeConfiguration, resourceAccessTimeout time.Duration) context.CancelFunc {
	grpcServer := grpc.NewServer()

	xdsServer := xds.NewServer(config, resourceAccessTimeout)
	dsServer := (*xdsGRPCServer)(xdsServer)

	// TODO: https://github.com/cilium/cilium/issues/5051
	// Implement IncrementalAggregatedResources to support Incremental xDS.
	//envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_secret.RegisterSecretDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_endpoint.RegisterEndpointDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_cluster.RegisterClusterDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_route.RegisterRouteDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_listener.RegisterListenerDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterNetworkPolicyDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterNetworkPolicyHostsDiscoveryServiceServer(grpcServer, dsServer)

	reflection.Register(grpcServer)

	go func() {
		log.Infof("Envoy: Starting xDS gRPC server listening on %s", listener.Addr())
		if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			log.WithError(err).Fatal("Envoy: Failed to serve xDS gRPC API")
		}
	}()

	return grpcServer.Stop
}

// xdsGRPCServer handles gRPC streaming discovery requests for the
// resource types supported by Cilium.
type xdsGRPCServer xds.Server

// TODO: https://github.com/cilium/cilium/issues/5051
// Implement IncrementalAggregatedResources also to support Incremental xDS.
//func (s *xdsGRPCServer) StreamAggregatedResources(stream envoy_service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
//	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, xds.AnyTypeURL)
//}

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

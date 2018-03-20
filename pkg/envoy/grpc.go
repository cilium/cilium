// Copyright 2018 Authors of Cilium
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

package envoy

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	envoy_service_discovery_v2 "github.com/cilium/cilium/pkg/envoy/envoy/service/discovery/v2"
	"github.com/cilium/cilium/pkg/envoy/xds"

	net_context "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	// ErrNotImplemented is the error returned by gRPC methods that are not
	// implemented by Cilium.
	ErrNotImplemented = errors.New("not implemented")
)

// StartXDSGRPCServer starts a gRPC server to serve xDS APIs using the given
// resource watcher and network listener.
// Returns a function that stops the GRPC server when called.
func StartXDSGRPCServer(listener net.Listener, ldsConfig, npdsConfig, nphdsConfig *xds.ResourceTypeConfiguration, resourceAccessTimeout time.Duration) context.CancelFunc {
	grpcServer := grpc.NewServer()

	xdsServer := xds.NewServer(map[string]*xds.ResourceTypeConfiguration{
		ListenerTypeURL:           ldsConfig,
		NetworkPolicyTypeURL:      npdsConfig,
		NetworkPolicyHostsTypeURL: nphdsConfig,
	}, resourceAccessTimeout)
	dsServer := (*xdsGRPCServer)(xdsServer)

	envoy_service_discovery_v2.RegisterAggregatedDiscoveryServiceServer(grpcServer, dsServer)
	envoy_api_v2.RegisterListenerDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterNetworkPolicyDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterNetworkPolicyHostsDiscoveryServiceServer(grpcServer, dsServer)

	reflection.Register(grpcServer)

	go func() {
		log.Infof("starting Envoy xDS gRPC server listening on %s", listener)
		if err := grpcServer.Serve(listener); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			log.WithError(err).Error("failed to serve Envoy xDS gRPC API")
		}
	}()

	return grpcServer.Stop
}

// xdsGRPCServer handles gRPC streaming discovery requests for the
// resource types supported by Cilium.
type xdsGRPCServer xds.Server

func (s *xdsGRPCServer) StreamAggregatedResources(stream envoy_service_discovery_v2.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, xds.AnyTypeURL)
}

func (s *xdsGRPCServer) StreamListeners(stream envoy_api_v2.ListenerDiscoveryService_StreamListenersServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, ListenerTypeURL)
}

func (s *xdsGRPCServer) FetchListeners(ctx net_context.Context, req *envoy_api_v2.DiscoveryRequest) (*envoy_api_v2.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamNetworkPolicies(stream cilium.NetworkPolicyDiscoveryService_StreamNetworkPoliciesServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, NetworkPolicyTypeURL)
}

func (s *xdsGRPCServer) FetchNetworkPolicies(ctx net_context.Context, req *envoy_api_v2.DiscoveryRequest) (*envoy_api_v2.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamNetworkPolicyHosts(stream cilium.NetworkPolicyHostsDiscoveryService_StreamNetworkPolicyHostsServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, NetworkPolicyHostsTypeURL)
}

func (s *xdsGRPCServer) FetchNetworkPolicyHosts(ctx net_context.Context, req *envoy_api_v2.DiscoveryRequest) (*envoy_api_v2.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

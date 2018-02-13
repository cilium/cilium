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

	"github.com/cilium/cilium/pkg/envoy/api"
	"github.com/cilium/cilium/pkg/envoy/xds"

	net_context "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	ListenerTypeURL           = "type.googleapis.com/envoy.api.v2.Listener"
	NetworkPolicyTypeURL      = "type.googleapis.com/envoy.api.v2.NetworkPolicy"
	NetworkPolicyHostsTypeURL = "type.googleapis.com/envoy.api.v2.NetworkPolicyHosts"
	RouteConfigurationTypeURL = "type.googleapis.com/envoy.api.v2.RouteConfiguration"
)

var (
	// ErrNotImplemented is the error returned by gRPC methods that are not
	// implemented by Cilium.
	ErrNotImplemented = errors.New("not implemented")
)

// StartXDSGRPCServer starts a gRPC server to serve xDS APIs using the given
// resource watcher and network listener.
// Returns a function that stops the GRPC server when called.
func StartXDSGRPCServer(listener net.Listener, ldsConfig, rdsConfig *xds.ResourceTypeConfiguration, resourceAccessTimeout time.Duration) context.CancelFunc {
	grpcServer := grpc.NewServer()

	xdsServer := xds.NewServer(map[string]*xds.ResourceTypeConfiguration{
		ListenerTypeURL:           ldsConfig,
		RouteConfigurationTypeURL: rdsConfig,
	}, resourceAccessTimeout)
	dsServer := (*xdsGRPCServer)(xdsServer)

	api.RegisterAggregatedDiscoveryServiceServer(grpcServer, dsServer)
	api.RegisterListenerDiscoveryServiceServer(grpcServer, dsServer)
	api.RegisterRouteDiscoveryServiceServer(grpcServer, dsServer)

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

func (s *xdsGRPCServer) StreamAggregatedResources(stream api.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, xds.AnyTypeURL)
}

func (s *xdsGRPCServer) StreamListeners(stream api.ListenerDiscoveryService_StreamListenersServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, ListenerTypeURL)
}

func (s *xdsGRPCServer) FetchListeners(ctx net_context.Context, req *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamRoutes(stream api.RouteDiscoveryService_StreamRoutesServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, RouteConfigurationTypeURL)
}

func (s *xdsGRPCServer) FetchRoutes(ctx net_context.Context, req *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

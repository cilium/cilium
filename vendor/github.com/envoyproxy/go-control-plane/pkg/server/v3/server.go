// Copyright 2018 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

// Package server provides an implementation of a streaming xDS server.
package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/envoyproxy/go-control-plane/pkg/server/config"
	"github.com/envoyproxy/go-control-plane/pkg/server/delta/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/rest/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	extensionconfigservice "github.com/envoyproxy/go-control-plane/envoy/service/extension/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimeservice "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	rlsconfigservice "github.com/envoyproxy/go-control-plane/ratelimit/service/ratelimit/v3"
)

// Server is a collection of handlers for streaming discovery requests.
type Server interface {
	endpointservice.EndpointDiscoveryServiceServer
	clusterservice.ClusterDiscoveryServiceServer
	routeservice.RouteDiscoveryServiceServer
	routeservice.ScopedRoutesDiscoveryServiceServer
	routeservice.VirtualHostDiscoveryServiceServer
	listenerservice.ListenerDiscoveryServiceServer
	discovery.AggregatedDiscoveryServiceServer
	secretservice.SecretDiscoveryServiceServer
	runtimeservice.RuntimeDiscoveryServiceServer
	extensionconfigservice.ExtensionConfigDiscoveryServiceServer
	rlsconfigservice.RateLimitConfigDiscoveryServiceServer

	rest.Server
	sotw.Server
	delta.Server
}

// Callbacks is a collection of callbacks inserted into the server operation.
// The callbacks are invoked synchronously.
type Callbacks interface {
	rest.Callbacks
	sotw.Callbacks
	delta.Callbacks
}

// CallbackFuncs is a convenience type for implementing the Callbacks interface.
type CallbackFuncs struct {
	StreamOpenFunc          func(context.Context, int64, string) error
	StreamClosedFunc        func(int64, *core.Node)
	DeltaStreamOpenFunc     func(context.Context, int64, string) error
	DeltaStreamClosedFunc   func(int64, *core.Node)
	StreamRequestFunc       func(int64, *discovery.DiscoveryRequest) error
	StreamResponseFunc      func(context.Context, int64, *discovery.DiscoveryRequest, *discovery.DiscoveryResponse)
	StreamDeltaRequestFunc  func(int64, *discovery.DeltaDiscoveryRequest) error
	StreamDeltaResponseFunc func(int64, *discovery.DeltaDiscoveryRequest, *discovery.DeltaDiscoveryResponse)
	FetchRequestFunc        func(context.Context, *discovery.DiscoveryRequest) error
	FetchResponseFunc       func(*discovery.DiscoveryRequest, *discovery.DiscoveryResponse)
}

var _ Callbacks = CallbackFuncs{}

// OnStreamOpen invokes StreamOpenFunc.
func (c CallbackFuncs) OnStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	if c.StreamOpenFunc != nil {
		return c.StreamOpenFunc(ctx, streamID, typeURL)
	}

	return nil
}

// OnStreamClosed invokes StreamClosedFunc.
func (c CallbackFuncs) OnStreamClosed(streamID int64, node *core.Node) {
	if c.StreamClosedFunc != nil {
		c.StreamClosedFunc(streamID, node)
	}
}

// OnDeltaStreamOpen invokes DeltaStreamOpenFunc.
func (c CallbackFuncs) OnDeltaStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	if c.DeltaStreamOpenFunc != nil {
		return c.DeltaStreamOpenFunc(ctx, streamID, typeURL)
	}

	return nil
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (c CallbackFuncs) OnDeltaStreamClosed(streamID int64, node *core.Node) {
	if c.DeltaStreamClosedFunc != nil {
		c.DeltaStreamClosedFunc(streamID, node)
	}
}

// OnStreamRequest invokes StreamRequestFunc.
func (c CallbackFuncs) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	if c.StreamRequestFunc != nil {
		return c.StreamRequestFunc(streamID, req)
	}

	return nil
}

// OnStreamResponse invokes StreamResponseFunc.
func (c CallbackFuncs) OnStreamResponse(ctx context.Context, streamID int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	if c.StreamResponseFunc != nil {
		c.StreamResponseFunc(ctx, streamID, req, resp)
	}
}

// OnStreamDeltaRequest invokes StreamDeltaResponseFunc
func (c CallbackFuncs) OnStreamDeltaRequest(streamID int64, req *discovery.DeltaDiscoveryRequest) error {
	if c.StreamDeltaRequestFunc != nil {
		return c.StreamDeltaRequestFunc(streamID, req)
	}

	return nil
}

// OnStreamDeltaResponse invokes StreamDeltaResponseFunc.
func (c CallbackFuncs) OnStreamDeltaResponse(streamID int64, req *discovery.DeltaDiscoveryRequest, resp *discovery.DeltaDiscoveryResponse) {
	if c.StreamDeltaResponseFunc != nil {
		c.StreamDeltaResponseFunc(streamID, req, resp)
	}
}

// OnFetchRequest invokes FetchRequestFunc.
func (c CallbackFuncs) OnFetchRequest(ctx context.Context, req *discovery.DiscoveryRequest) error {
	if c.FetchRequestFunc != nil {
		return c.FetchRequestFunc(ctx, req)
	}

	return nil
}

// OnFetchResponse invoked FetchResponseFunc.
func (c CallbackFuncs) OnFetchResponse(req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	if c.FetchResponseFunc != nil {
		c.FetchResponseFunc(req, resp)
	}
}

// NewServer creates handlers from a config watcher and callbacks.
func NewServer(ctx context.Context, config cache.Cache, callbacks Callbacks, opts ...config.XDSOption) Server {
	return NewServerAdvanced(rest.NewServer(config, callbacks),
		sotw.NewServer(ctx, config, callbacks, opts...),
		delta.NewServer(ctx, config, callbacks, opts...),
	)
}

func NewServerAdvanced(restServer rest.Server, sotwServer sotw.Server, deltaServer delta.Server) Server {
	return &server{rest: restServer, sotw: sotwServer, delta: deltaServer}
}

type server struct {
	rest  rest.Server
	sotw  sotw.Server
	delta delta.Server
}

func (s *server) StreamHandler(stream stream.Stream, typeURL string) error {
	return s.sotw.StreamHandler(stream, typeURL)
}

func (s *server) StreamAggregatedResources(stream discovery.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	return s.StreamHandler(stream, resource.AnyType)
}

func (s *server) StreamEndpoints(stream endpointservice.EndpointDiscoveryService_StreamEndpointsServer) error {
	return s.StreamHandler(stream, resource.EndpointType)
}

func (s *server) StreamClusters(stream clusterservice.ClusterDiscoveryService_StreamClustersServer) error {
	return s.StreamHandler(stream, resource.ClusterType)
}

func (s *server) StreamRoutes(stream routeservice.RouteDiscoveryService_StreamRoutesServer) error {
	return s.StreamHandler(stream, resource.RouteType)
}

func (s *server) StreamScopedRoutes(stream routeservice.ScopedRoutesDiscoveryService_StreamScopedRoutesServer) error {
	return s.StreamHandler(stream, resource.ScopedRouteType)
}

func (s *server) StreamListeners(stream listenerservice.ListenerDiscoveryService_StreamListenersServer) error {
	return s.StreamHandler(stream, resource.ListenerType)
}

func (s *server) StreamSecrets(stream secretservice.SecretDiscoveryService_StreamSecretsServer) error {
	return s.StreamHandler(stream, resource.SecretType)
}

func (s *server) StreamRuntime(stream runtimeservice.RuntimeDiscoveryService_StreamRuntimeServer) error {
	return s.StreamHandler(stream, resource.RuntimeType)
}

func (s *server) StreamExtensionConfigs(stream extensionconfigservice.ExtensionConfigDiscoveryService_StreamExtensionConfigsServer) error {
	return s.StreamHandler(stream, resource.ExtensionConfigType)
}

func (s *server) StreamRlsConfigs(stream rlsconfigservice.RateLimitConfigDiscoveryService_StreamRlsConfigsServer) error {
	return s.StreamHandler(stream, resource.RateLimitConfigType)
}

// VHDS doesn't support SOTW requests, so no handler for it exists.

// Fetch is the universal fetch method.
func (s *server) Fetch(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	return s.rest.Fetch(ctx, req)
}

func (s *server) FetchEndpoints(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.EndpointType
	return s.Fetch(ctx, req)
}

func (s *server) FetchClusters(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.ClusterType
	return s.Fetch(ctx, req)
}

func (s *server) FetchRoutes(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.RouteType
	return s.Fetch(ctx, req)
}

func (s *server) FetchScopedRoutes(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.ScopedRouteType
	return s.Fetch(ctx, req)
}

func (s *server) FetchListeners(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.ListenerType
	return s.Fetch(ctx, req)
}

func (s *server) FetchSecrets(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.SecretType
	return s.Fetch(ctx, req)
}

func (s *server) FetchRuntime(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.RuntimeType
	return s.Fetch(ctx, req)
}

func (s *server) FetchExtensionConfigs(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.ExtensionConfigType
	return s.Fetch(ctx, req)
}

func (s *server) FetchRlsConfigs(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.Unavailable, "empty request")
	}
	req.TypeUrl = resource.RateLimitConfigType
	return s.Fetch(ctx, req)
}

// VHDS doesn't support REST requests, so no handler exists for this.

func (s *server) DeltaStreamHandler(stream stream.DeltaStream, typeURL string) error {
	return s.delta.DeltaStreamHandler(stream, typeURL)
}

func (s *server) DeltaAggregatedResources(stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	return s.DeltaStreamHandler(stream, resource.AnyType)
}

func (s *server) DeltaEndpoints(stream endpointservice.EndpointDiscoveryService_DeltaEndpointsServer) error {
	return s.DeltaStreamHandler(stream, resource.EndpointType)
}

func (s *server) DeltaClusters(stream clusterservice.ClusterDiscoveryService_DeltaClustersServer) error {
	return s.DeltaStreamHandler(stream, resource.ClusterType)
}

func (s *server) DeltaRoutes(stream routeservice.RouteDiscoveryService_DeltaRoutesServer) error {
	return s.DeltaStreamHandler(stream, resource.RouteType)
}

func (s *server) DeltaScopedRoutes(stream routeservice.ScopedRoutesDiscoveryService_DeltaScopedRoutesServer) error {
	return s.DeltaStreamHandler(stream, resource.ScopedRouteType)
}

func (s *server) DeltaListeners(stream listenerservice.ListenerDiscoveryService_DeltaListenersServer) error {
	return s.DeltaStreamHandler(stream, resource.ListenerType)
}

func (s *server) DeltaSecrets(stream secretservice.SecretDiscoveryService_DeltaSecretsServer) error {
	return s.DeltaStreamHandler(stream, resource.SecretType)
}

func (s *server) DeltaRuntime(stream runtimeservice.RuntimeDiscoveryService_DeltaRuntimeServer) error {
	return s.DeltaStreamHandler(stream, resource.RuntimeType)
}

func (s *server) DeltaExtensionConfigs(stream extensionconfigservice.ExtensionConfigDiscoveryService_DeltaExtensionConfigsServer) error {
	return s.DeltaStreamHandler(stream, resource.ExtensionConfigType)
}

func (s *server) DeltaVirtualHosts(stream routeservice.VirtualHostDiscoveryService_DeltaVirtualHostsServer) error {
	return s.DeltaStreamHandler(stream, resource.VirtualHostType)
}

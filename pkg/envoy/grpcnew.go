// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"net"

	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	sotw "github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	envoy_server "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// // ErrNotImplemented is the error returned by gRPC methods that are not
// // implemented by Cilium.
// var ErrNotImplemented = errors.New("not implemented")

// startadsGRPCServer starts a gRPC server to serve ADS APIs.
// Returns a function that stops the GRPC server when called.
func (s *adsServer) startAdsGRPCServer(ctx context.Context, cache cache.SnapshotCache) error {
	listener, err := s.newSocketListener()
	if err != nil {
		return fmt.Errorf("failed to create socket listener: %w", err)
	}

	callbacks := xdsnew.LoggingCallbacks{Log: s.logger}
	server := envoy_server.NewServer(context.Background(), cache, callbacks, sotw.WithOrderedADS())

	grpcServer := grpc.NewServer()
	envoy_service_discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)

	// TODO: https://github.com/cilium/cilium/issues/5051
	// Implement IncrementalAggregatedResources to support Incremental xDS.
	// envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(grpcServer, dsServer)
	// cilium.RegisterNetworkPolicyDiscoveryServiceServer(grpcServer, dsServer)
	// cilium.RegisterNetworkPolicyHostsDiscoveryServiceServer(grpcServer, dsServer)

	reflection.Register(grpcServer)

	ctx, cancel := context.WithTimeout(ctx, s.config.policyRestoreTimeout)
	defer cancel()
	s.stopFunc = grpcServer.Stop

	s.logger.Info("Envoy: Starting xDS gRPC server listening",
		logfields.Address, listener.Addr(),
	)
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Error("Envoy: Failed to serve xDS gRPC API",
			logfields.Error, err,
		)
	}

	return nil
}

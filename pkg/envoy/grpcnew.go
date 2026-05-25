// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	envoy_server "github.com/envoyproxy/go-control-plane/pkg/server/v3"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// startAdsGRPCServer runs a gRPC server to serve ADS APIs. Returns on error or
// when ctx is cancelled.
func (s *adsServer) startAdsGRPCServer(ctx context.Context) error {
	listener, err := s.newSocketListener()
	if err != nil {
		return fmt.Errorf("failed to create socket listener: %w", err)
	}

	callbacks := callbacks.ChainedCallbacks{
		callbacks.LoggingCallbacks{Log: s.logger},
		s.cache.GetCompletionCallbacks(),
	}
	server := envoy_server.NewServer(context.Background(), s.cache, callbacks,
		sotw.WithOrderedADS(),
		sotw.DeactivateLegacyWildcardForTypes([]string{SecretTypeURL}),
	)

	grpcServer := grpc.NewServer()
	envoy_service_discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)

	reflection.Register(grpcServer)

	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()

	ctx, cancel := context.WithTimeout(ctx, s.config.policyRestoreTimeout)
	defer cancel()
	s.stopFunc = grpcServer.Stop

	s.logger.Info("Envoy: Starting xDS gRPC server listening",
		logfields.Address, listener.Addr(),
	)

	go func() {
		<-serverCtx.Done()
		grpcServer.Stop()
		if s.socketPath != "" {
			_ = os.Remove(s.socketPath)
		}
	}()

	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Error("Envoy: Failed to serve xDS gRPC API",
			logfields.Error, err,
		)
	}

	return nil
}

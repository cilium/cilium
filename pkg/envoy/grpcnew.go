// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"net"

	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	envoy_server "github.com/envoyproxy/go-control-plane/pkg/server/v3"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// startAdsGRPCServer starts a gRPC server to serve ADS APIs.
// Returns a function that stops the GRPC server when called.
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

	ctx, cancel := context.WithTimeout(ctx, s.config.policyRestoreTimeout)
	defer cancel()
	s.stopFunc = grpcServer.Stop

	if s.restorerPromise != nil {
		s.logger.Info("Envoy: Waiting for endpoint restorer before serving xDS resources...")
		restorer, err := s.restorerPromise.Await(ctx)
		if err == nil && restorer != nil {
			s.logger.Info("Envoy: Waiting for endpoint restoration before serving xDS resources...")
			err = restorer.WaitForInitialPolicy(ctx)
		}
		if errors.Is(err, context.Canceled) {
			s.logger.Debug("Envoy: xDS server stopped before started serving")
			return err
		}
		if errors.Is(err, context.DeadlineExceeded) {
			s.logger.Warn("Envoy: Endpoint policy restoration took longer than configured restore timeout, starting serving resources to Envoy",
				logfields.Duration, s.config.policyRestoreTimeout,
			)
		}
	}

	s.logger.Info("Envoy: Starting xDS gRPC server listening",
		logfields.Address, listener.Addr(),
	)

	// Start listening to IPCache events to populate NPHDS resources.
	startNPHDSIPCacheListener(s.logger, s.ipCache, s)

	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Error("Envoy: Failed to serve xDS gRPC API",
			logfields.Error, err,
		)
	}

	return nil
}

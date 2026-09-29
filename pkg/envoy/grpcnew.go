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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

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

	server := envoy_server.NewServer(context.Background(), s.cache, s.newCallbacks(),
		sotw.WithOrderedADS(),
		// EDS, RDS and SDS use named subscriptions; an initial empty list
		// means no subscription. LDS, CDS, NPDS and NPHDS retain wildcard mode.
		sotw.DeactivateLegacyWildcardForTypes([]string{EndpointTypeURL, RouteTypeURL, SecretTypeURL}),
	)

	grpcServer := grpc.NewServer()
	envoy_service_discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)

	reflection.Register(grpcServer)

	restoreCtx, cancel := context.WithTimeout(ctx, s.config.policyRestoreTimeout)
	defer cancel()
	s.stopFunc = grpcServer.Stop

	s.mutex.Lock()
	restorerPromise := s.restorerPromise
	s.mutex.Unlock()
	if restorerPromise != nil {
		s.logger.Info("Envoy: Waiting for endpoint restorer before serving xDS resources...")
		restorer, err := restorerPromise.Await(restoreCtx)
		if err == nil && restorer != nil {
			s.logger.Info("Envoy: Waiting for endpoint restoration before serving xDS resources...")
			err = restorer.WaitForInitialPolicy(restoreCtx)
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
		s.markRestoreCompleted()
	}

	s.logger.Info("Envoy: Starting xDS gRPC server listening",
		logfields.Address, listener.Addr(),
	)

	ctx, cancel = context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
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

func (s *adsServer) newCallbacks() callbacks.ChainedCallbacks {
	return callbacks.ChainedCallbacks{
		envoy_server.CallbackFuncs{
			StreamRequestFunc: func(_ int64, req *envoy_service_discovery.DiscoveryRequest) error {
				// go-control-plane restores the first request's node on subsequent
				// requests before invoking callbacks. Validate before any callback
				// creates completion state or starts the NPHDS IPCache dump.
				nodeID := req.GetNode().GetId()
				if nodeID == "" {
					return status.Error(codes.InvalidArgument, "xDS node ID is required")
				}
				if !s.cache.HasNode(nodeID) {
					return status.Errorf(codes.NotFound, "unknown xDS node %q", nodeID)
				}
				return nil
			},
		},
		callbacks.LoggingCallbacks{Log: s.logger},
		s.cache.GetCompletionCallbacks(),
		newNPHDSIPCacheListenerCallbacks(s.logger, s.ipCache, s),
	}
}

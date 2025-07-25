// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/server"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/daemon/cmd/cni"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

const (
	endpointAPIModuleID = "endpoint-api"
	endpointAPIGroup    = "endpoint"

	endpointAPIMiddlewareMaxWaitTime = 3 * time.Second
)

// Cell provides the Endpoint API.
var Cell = cell.Module(
	endpointAPIModuleID,
	"Provides Endpoint API",

	// Endpoint API handlers
	cell.Provide(newEndpointAPIHandler),

	// Custom middleware for endpoint APIs.
	cell.Provide(newEndpointAPIMiddleware),

	// EndpointAPIManager provides functionality to support the API
	cell.Provide(newEndpointAPIManager),

	// EndpointCreationManager keeps track of all currently ongoing endpoint creations
	cell.ProvidePrivate(newEndpointCreationManager),

	// Processes endpoint deletions that occurred while the agent was down.
	// This starts before the API server as endpoint api handlers depends on
	// the 'DeletionQueue' provided by this cell.
	cell.ProvidePrivate(newDeletionQueue),

	// unlockAfterAPIServer registers a start hook that runs after API server
	// has started and the deletion queue has been drained to unlock the
	// delete queue and thus allow CNI plugin to proceed.
	cell.Invoke(unlockAfterAPIServer),
)

type endpointAPIManagerParams struct {
	cell.In

	Logger *slog.Logger

	EndpointManager   endpointmanager.EndpointManager
	EndpointCreator   endpointcreator.EndpointCreator
	EndpointCreations EndpointCreationManager
	EndpointMetadata  endpointmetadata.EndpointMetadataFetcher

	BandwidthManager datapath.BandwidthManager
	Clientset        k8sClient.Clientset
	CNIConfigManager cni.CNIConfigManager
	IPAM             *ipam.IPAM
}

func newEndpointAPIManager(params endpointAPIManagerParams) EndpointAPIManager {
	return &endpointAPIManager{
		logger:            params.Logger,
		endpointManager:   params.EndpointManager,
		endpointCreator:   params.EndpointCreator,
		endpointCreations: params.EndpointCreations,
		endpointMetadata:  params.EndpointMetadata,
		bandwidthManager:  params.BandwidthManager,
		clientset:         params.Clientset,
		cniConfigManager:  params.CNIConfigManager,
		ipam:              params.IPAM,
	}
}

type endpointAPIHandlerParams struct {
	cell.In

	Logger        *slog.Logger
	APILimiterSet *rate.APILimiterSet

	EndpointManager    endpointmanager.EndpointManager
	EndpointCreator    endpointcreator.EndpointCreator
	EndpointAPIManager EndpointAPIManager

	// The API handlers depend on [deletionQueue] to make sure the deletion lock file is created and locked
	// before the API server starts.
	DeletionQueue *DeletionQueue
}

type endpointAPIHandlerOut struct {
	cell.Out

	EndpointDeleteEndpointHandler        endpointapi.DeleteEndpointHandler
	EndpointDeleteEndpointIDHandler      endpointapi.DeleteEndpointIDHandler
	EndpointGetEndpointHandler           endpointapi.GetEndpointHandler
	EndpointGetEndpointIDConfigHandler   endpointapi.GetEndpointIDConfigHandler
	EndpointGetEndpointIDHandler         endpointapi.GetEndpointIDHandler
	EndpointGetEndpointIDHealthzHandler  endpointapi.GetEndpointIDHealthzHandler
	EndpointGetEndpointIDLabelsHandler   endpointapi.GetEndpointIDLabelsHandler
	EndpointGetEndpointIDLogHandler      endpointapi.GetEndpointIDLogHandler
	EndpointPatchEndpointIDConfigHandler endpointapi.PatchEndpointIDConfigHandler
	EndpointPatchEndpointIDHandler       endpointapi.PatchEndpointIDHandler
	EndpointPatchEndpointIDLabelsHandler endpointapi.PatchEndpointIDLabelsHandler
	EndpointPutEndpointIDHandler         endpointapi.PutEndpointIDHandler
}

func newEndpointAPIHandler(params endpointAPIHandlerParams) endpointAPIHandlerOut {
	return endpointAPIHandlerOut{
		EndpointDeleteEndpointHandler: &EndpointDeleteEndpointHandler{
			logger:             params.Logger,
			apiLimiterSet:      params.APILimiterSet,
			endpointManager:    params.EndpointManager,
			endpointAPIManager: params.EndpointAPIManager,
		},
		EndpointDeleteEndpointIDHandler: &EndpointDeleteEndpointIDHandler{
			logger:             params.Logger,
			apiLimiterSet:      params.APILimiterSet,
			endpointManager:    params.EndpointManager,
			endpointAPIManager: params.EndpointAPIManager,
		},
		EndpointGetEndpointHandler: &EndpointGetEndpointHandler{
			logger:          params.Logger,
			apiLimiterSet:   params.APILimiterSet,
			endpointManager: params.EndpointManager,
		},
		EndpointGetEndpointIDConfigHandler: &EndpointGetEndpointIDConfigHandler{
			logger:          params.Logger,
			apiLimiterSet:   params.APILimiterSet,
			endpointManager: params.EndpointManager,
		},
		EndpointGetEndpointIDHandler: &EndpointGetEndpointIDHandler{
			logger:          params.Logger,
			apiLimiterSet:   params.APILimiterSet,
			endpointManager: params.EndpointManager,
		},
		EndpointGetEndpointIDHealthzHandler: &EndpointGetEndpointIDHealthzHandler{
			logger:          params.Logger,
			apiLimiterSet:   params.APILimiterSet,
			endpointManager: params.EndpointManager,
		},
		EndpointGetEndpointIDLabelsHandler: &EndpointGetEndpointIDLabelsHandler{
			logger:          params.Logger,
			apiLimiterSet:   params.APILimiterSet,
			endpointManager: params.EndpointManager,
		},
		EndpointGetEndpointIDLogHandler: &EndpointGetEndpointIDLogHandler{
			logger:          params.Logger,
			apiLimiterSet:   params.APILimiterSet,
			endpointManager: params.EndpointManager,
		},
		EndpointPatchEndpointIDConfigHandler: &EndpointPatchEndpointIDConfigHandler{
			logger:             params.Logger,
			apiLimiterSet:      params.APILimiterSet,
			endpointAPIManager: params.EndpointAPIManager,
		},
		EndpointPatchEndpointIDHandler: &EndpointPatchEndpointIDHandler{
			logger:          params.Logger,
			apiLimiterSet:   params.APILimiterSet,
			endpointManager: params.EndpointManager,
			endpointCreator: params.EndpointCreator,
		},
		EndpointPatchEndpointIDLabelsHandler: &EndpointPatchEndpointIDLabelsHandler{
			logger:             params.Logger,
			apiLimiterSet:      params.APILimiterSet,
			endpointManager:    params.EndpointManager,
			endpointAPIManager: params.EndpointAPIManager,
		},
		EndpointPutEndpointIDHandler: &EndpointPutEndpointIDHandler{
			logger:             params.Logger,
			apiLimiterSet:      params.APILimiterSet,
			endpointAPIManager: params.EndpointAPIManager,
		},
	}
}

type endpointAPIMiddlewareParams struct {
	cell.In

	Logger                       *slog.Logger
	EndpointStateRestorerPromise promise.Promise[endpointstate.Restorer]
	DeletionQueue                *DeletionQueue
}

type Middleware struct {
	logger                       *slog.Logger
	endpointStateRestorerPromise promise.Promise[endpointstate.Restorer]
	deletionQueue                *DeletionQueue
}

func newEndpointAPIMiddleware(params endpointAPIMiddlewareParams) *Middleware {
	return &Middleware{
		logger:                       params.Logger,
		endpointStateRestorerPromise: params.EndpointStateRestorerPromise,
		deletionQueue:                params.DeletionQueue,
	}
}

// WaitReady waits for API Middleware to be completely ready for interaction with
// external components.
// Currently middleware readiness is evaluated by making sure that offline delete
// queue processing is complete, which in turn indicates that Endpoint state restoration
// is complete.
func (m *Middleware) WaitReady(ctx context.Context) error {
	return m.deletionQueue.Wait(ctx)
}

// Configures endpoint api subsystem middleware for the provided API server and
// open-api Spec.
func (m *Middleware) Configure(Spec *server.Spec, Server *server.Server) {
	for _, ep := range Spec.APIGroups[endpointAPIGroup] {
		// Skip configuring the middleware for GET endpoints.
		if ep.Method == "GET" {
			continue
		}

		Server.GetAPI().AddMiddlewareFor(ep.Method, ep.Path, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeout(r.Context(), endpointAPIMiddlewareMaxWaitTime)
				defer cancel()

				// EndpointRestorer promise is resolved once the daemon start hook is executed.
				// Resolved restorer indicates that restored endpoints are exposed to EndpointManager
				// which in turn means that requests can now be processed by the endpoint API manager.
				//
				// NOTE: A resolved EndpointStateRestorer promise doesn't indicate that the regeneration
				// for corresponding endpoints is also complete.
				if _, err := m.endpointStateRestorerPromise.Await(ctx); err != nil {
					m.logger.Debug("Failed waiting for EndpointState restorer promise to resolve",
						logfields.Method, r.Method,
						logfields.Error, err)
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}

				// Once the Endpoint restore promise is resolved, DeletionQueue acquires the lock
				// on offline queue. In order to avoid missing any subsequent deletes requests,
				// accept calls on DELETE endpoints but wait for deletion queue draining before accepting
				// other methods.
				if ep.Method != "DELETE" {
					if err := m.WaitReady(ctx); err != nil {
						m.logger.Debug("Failed waiting for API middleware readiness",
							logfields.Method, r.Method,
							logfields.Error, err)
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
				}

				next.ServeHTTP(w, r)
			})
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/daemon/cmd/cni"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/rate"
)

const endpointAPIModuleID = "endpoint-api"

// Cell provides the Endpoint API.
var Cell = cell.Module(
	endpointAPIModuleID,
	"Provides Endpoint API",

	// Endpoint API handlers
	cell.Provide(newEndpointAPIHandler),

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

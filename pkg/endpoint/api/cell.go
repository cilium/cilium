// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/daemon/cmd/cni"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

// Cell provides the Endpoint API.
var Cell = cell.Module(
	"endpoint-api",
	"Provides Endpoint API",

	// EndpointAPIManager provides functionality to support the API
	cell.Provide(newEndpointAPIManager),

	// EndpointCreationManager keeps track of all currently ongoing endpoint creations
	cell.Provide(newEndpointCreationManager),

	// Processes endpoint deletions that occurred while the agent was down.
	// This starts before the API server as endpoint api handlers depends on
	// the 'DeletionQueue' provided by this cell.
	cell.Provide(newDeletionQueue),

	// unlockAfterAPIServer registers a start hook that runs after API server
	// has started and the deletion queue has been drained to unlock the
	// delete queue and thus allow CNI plugin to proceed.
	cell.Invoke(unlockAfterAPIServer),
)

type endpointAPIManagerParams struct {
	cell.In

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

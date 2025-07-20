// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointapi "github.com/cilium/cilium/pkg/endpoint/api"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	"github.com/cilium/cilium/pkg/endpoint/watchdog"
	"github.com/cilium/cilium/pkg/endpointcleanup"
	"github.com/cilium/cilium/pkg/endpointmanager"
)

// Endpoint control-plane meta cell.
var Cell = cell.Group(
	// EndpointManager maintains a collection of the locally running endpoints.
	endpointmanager.Cell,

	// EndpointCreator helps creating endpoints
	endpointcreator.Cell,

	// Provides the EndpointMetadataFetcher that provides k8s metadata for endpoints.
	endpointmetadata.Cell,

	// Provides the Endpoint REST API
	endpointapi.Cell,

	// Register the startup procedure to remove stale CiliumEndpoints referencing pods no longer
	// managed by Cilium.
	endpointcleanup.Cell,

	// RegeneratorCell provides extra options and utilities for endpoints regeneration.
	endpoint.RegeneratorCell,

	// Cell triggers a job to ensure device tc programs remain loaded.
	watchdog.Cell,
)

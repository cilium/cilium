// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/cilium/hive/cell"
)

// Cell provides the Endpoint API.
var Cell = cell.Module(
	"endpoint-api",
	"Provides Endpoint API",

	// EndpointCreationManager keeps track of all currently ongoing endpoint creations
	cell.Provide(newEndpointCreationManager),
)

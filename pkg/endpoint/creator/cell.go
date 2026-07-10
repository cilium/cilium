// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package creator

import (
	"github.com/cilium/hive/cell"
)

// Cell provides the EndpointCreator API for creating and parsing Endpoints.
var Cell = cell.Module(
	"endpoint-creator",
	"API for creating and parsing Endpoints",

	cell.Provide(newEndpointCreator),
)

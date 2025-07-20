// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"github.com/cilium/hive/cell"
)

// Cell provides the EndpointMetadataFetcher that provides k8s metadata for endpoints.
var Cell = cell.Module(
	"endpoint-metadata",
	"Provides Kubernetes metadata for endpoints",

	cell.Provide(NewEndpointMetadataFetcher),
)

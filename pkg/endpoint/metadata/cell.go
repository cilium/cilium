// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/k8s/watchers"
)

// Cell provides the EndpointMetadataFetcher that provides k8s metadata for endpoints.
var Cell = cell.Module(
	"endpoint-metadata",
	"Provides Kubernetes metadata for endpoints",

	cell.Provide(NewEndpointMetadataFetcher),
	cell.ProvidePrivate(func(k8sWatcher *watchers.K8sWatcher) k8sPodMetadataFetcher {
		return k8sWatcher
	}),
)

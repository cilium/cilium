// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the EndpointMetadataFetcher that provides k8s metadata for endpoints.
var Cell = cell.Module(
	"endpoint-metadata",
	"Provides Kubernetes metadata for endpoints",

	cell.Provide(newEndpointMetadataFetcher),
)

func newEndpointMetadataFetcher(logger *slog.Logger, config *option.DaemonConfig, k8sWatcher *watchers.K8sWatcher) EndpointMetadataFetcher {
	return NewEndpointMetadataFetcher(logger, config, k8sWatcher)
}

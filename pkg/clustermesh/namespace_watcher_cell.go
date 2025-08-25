// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"os"
	"strconv"

	"github.com/cilium/hive/cell"
)

// NamespaceWatcherCell provides namespace-based export control for ClusterMesh.
var NamespaceWatcherCell = cell.Module(
	"namespace-watcher",
	"Namespace-based export control for ClusterMesh",

	cell.Provide(
		newNamespaceWatcherConfig,
		newGlobalNamespaceTracker,
	),
)

type namespaceWatcherConfigParams struct {
	cell.In
}

func newNamespaceWatcherConfig(params namespaceWatcherConfigParams) NamespaceWatcherConfig {
	// Read the configuration from environment variable following the same pattern as cluster-id
	defaultGlobal := false // Default to false for security
	if envVal := os.Getenv("CLUSTERMESH_DEFAULT_GLOBAL_NAMESPACE"); envVal != "" {
		if parsed, err := strconv.ParseBool(envVal); err == nil {
			defaultGlobal = parsed
		}
	}

	return NamespaceWatcherConfig{DefaultGlobalNamespace: defaultGlobal}
}

// newGlobalNamespaceTracker creates and registers the namespace watcher.
func newGlobalNamespaceTracker(params NamespaceWatcherParams) GlobalNamespaceTracker {
	return RegisterNamespaceWatcher(params)
}

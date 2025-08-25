// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespacewatcher

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// NamespaceWatcherParams provides the dependencies for the namespace watcher.
type NamespaceWatcherParams struct {
	cell.In

	Logger     *slog.Logger
	JobGroup   job.Group
	Namespaces resource.Resource[*slim_corev1.Namespace]
	Config     Config
}

// Cell provides namespace-based export control for ClusterMesh.
// The Config must be provided externally by the calling module.
var Cell = cell.Module(
	"namespace-watcher",
	"Namespace-based export control for ClusterMesh",

	cell.Provide(newGlobalNamespaceTracker),
)

// newGlobalNamespaceTracker creates and registers the namespace watcher.
// The config parameter is provided externally by the calling module.
func newGlobalNamespaceTracker(params NamespaceWatcherParams) GlobalNamespaceTracker {
	// Ensure required dependencies are available
	if params.Namespaces == nil {
		params.Logger.Error("namespace resource is required for namespace watcher")
		return nil
	}

	watcher := NewNamespaceWatcher(params.Logger, params.Config, params.Namespaces)

	params.JobGroup.Add(
		job.OneShot(
			"namespace-watcher",
			func(ctx context.Context, _ cell.Health) error {
				nsStore, err := watcher.namespaceResource.Store(ctx)
				if err != nil {
					return err
				}
				watcher.nsStore = nsStore

				// Start processing namespace events
				for event := range params.Namespaces.Events(ctx) {
					event.Done(nil)

					switch event.Kind {
					case resource.Sync:
						params.Logger.Info("Initial list of namespaces successfully received from Kubernetes")
					case resource.Upsert:
						watcher.updateNamespace(event.Object)
					case resource.Delete:
						watcher.deleteNamespace(event.Object)
					}
				}
				return nil
			},
		),
	)

	return watcher
}

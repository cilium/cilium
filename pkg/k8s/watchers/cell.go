// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the global k8s watcher.
var Cell = cell.Module(
	"k8s-watcher",
	"K8s Watcher",

	cell.Provide(newK8sWatcher),
	cell.ProvidePrivate(newK8sPodWatcher),
	cell.Provide(newK8sCiliumNodeWatcher),
	cell.ProvidePrivate(newK8sCiliumEndpointsWatcher),
	cell.Provide(newK8sEventReporter),
)

type ResourceGroupFunc = func(logger *slog.Logger, cfg WatcherConfiguration) (resourceGroups, waitForCachesOnly []string)

type k8sWatcherParams struct {
	cell.In

	Logger *slog.Logger

	K8sEventReporter          *K8sEventReporter
	K8sPodWatcher             *K8sPodWatcher
	K8sCiliumNodeWatcher      *K8sCiliumNodeWatcher
	K8sCiliumEndpointsWatcher *K8sCiliumEndpointsWatcher

	AgentConfig *option.DaemonConfig

	Clientset         k8sClient.Clientset
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups
	K8sCacheStatus    k8sSynced.CacheStatus
	ResourceGroupsFn  ResourceGroupFunc

	KVStoreClient kvstore.Client
}

func newK8sWatcher(params k8sWatcherParams) *K8sWatcher {
	return newWatcher(
		params.Logger,
		params.ResourceGroupsFn,
		params.Clientset,
		params.K8sPodWatcher,
		params.K8sCiliumNodeWatcher,
		params.K8sCiliumEndpointsWatcher,
		params.K8sEventReporter,
		params.K8sResourceSynced,
		params.K8sCacheStatus,
		params.K8sAPIGroups,
		params.AgentConfig,
		params.KVStoreClient,
	)
}

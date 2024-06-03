// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/cilium/hive/cell"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgp/speaker"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/service"
)

// Cell provides the global k8s watcher.
var Cell = cell.Module(
	"k8s-watcher",
	"K8s Watcher",

	cell.Provide(newK8sWatcher),
	cell.ProvidePrivate(newK8sPodWatcher),
	cell.ProvidePrivate(newK8sCiliumNodeWatcher),
	cell.ProvidePrivate(newK8sEventReporter),
)

type k8sWatcherParams struct {
	cell.In

	K8sEventReporter     *K8sEventReporter
	K8sPodWatcher        *K8sPodWatcher
	K8sCiliumNodeWatcher *K8sCiliumNodeWatcher

	AgentConfig *option.DaemonConfig

	Clientset         k8sClient.Clientset
	Resources         agentK8s.Resources
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups
	EndpointManager   endpointmanager.EndpointManager
	PolicyUpdater     *policy.Updater
	IPCache           *ipcache.IPCache
	ServiceCache      *k8s.ServiceCache
	ServiceManager    service.ServiceManager
	LRPManager        *redirectpolicy.Manager
	MetalLBBgpSpeaker speaker.MetalLBBgpSpeaker
}

func newK8sWatcher(params k8sWatcherParams) *K8sWatcher {
	return newWatcher(
		params.Clientset,
		params.K8sPodWatcher,
		params.K8sCiliumNodeWatcher,
		params.K8sEventReporter,
		params.K8sResourceSynced,
		params.K8sAPIGroups,
		params.EndpointManager,
		params.PolicyUpdater,
		params.ServiceManager,
		params.LRPManager,
		params.MetalLBBgpSpeaker,
		params.AgentConfig,
		params.IPCache,
		params.Resources,
		params.ServiceCache,
	)
}

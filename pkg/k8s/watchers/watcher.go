// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/util/runtime"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

const (
	k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
	k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
	k8sAPIGroupCiliumCIDRGroupV2                = "cilium/v2::CiliumCIDRGroup"
	k8sAPIGroupCiliumNodeV2                     = "cilium/v2::CiliumNode"
	k8sAPIGroupCiliumEndpointV2                 = "cilium/v2::CiliumEndpoint"
	k8sAPIGroupCiliumLocalRedirectPolicyV2      = "cilium/v2::CiliumLocalRedirectPolicy"
	k8sAPIGroupCiliumEndpointSliceV2Alpha1      = "cilium/v2alpha1::CiliumEndpointSlice"
)

func init() {
	// Replace error handler with our own
	runtime.ErrorHandlers = []runtime.ErrorHandler{
		k8s.K8sErrorHandler,
	}
}

type endpointManager interface {
	LookupCEPName(string) *endpoint.Endpoint
	GetEndpoints() []*endpoint.Endpoint
	GetHostEndpoint() *endpoint.Endpoint
	GetEndpointsByPodName(string) []*endpoint.Endpoint
	WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error
	UpdatePolicyMaps(context.Context, *sync.WaitGroup) *sync.WaitGroup
}

type nodeManager interface {
	NodeDeleted(n nodeTypes.Node)
	NodeUpdated(n nodeTypes.Node)
	NodeSync()
}

type policyManager interface {
	TriggerPolicyUpdates(reason string)
}

type cgroupManager interface {
	OnAddPod(pod *slim_corev1.Pod)
	OnUpdatePod(oldPod, newPod *slim_corev1.Pod)
	OnDeletePod(pod *slim_corev1.Pod)
}

type CacheAccessK8SWatcher interface {
	GetCachedPod(namespace, name string) (*slim_corev1.Pod, error)
}

type ipcacheManager interface {
	// GH-21142: Re-evaluate the need for these APIs
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (namedPortsChanged bool, err error)
	LookupByIP(IP string) (ipcache.Identity, bool)
	Delete(IP string, source source.Source) (namedPortsChanged bool)

	UpsertMetadata(prefix cmtypes.PrefixCluster, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
	RemoveLabelsExcluded(lbls labels.Labels, toExclude map[cmtypes.PrefixCluster]struct{}, resource ipcacheTypes.ResourceID)
	DeleteOnMetadataMatch(IP string, source source.Source, namespace, name string) (namedPortsChanged bool)
}

type hostNetworkManager interface {
	AddNoTrackHostPorts(namespace, name string, ports []string)
	RemoveNoTrackHostPorts(namespace, name string)
}

type K8sWatcher struct {
	logger           *slog.Logger
	resourceGroupsFn func(logger *slog.Logger, cfg WatcherConfiguration) (resourceGroups, waitForCachesOnly []string)

	clientset client.Clientset

	k8sEventReporter          *K8sEventReporter
	k8sPodWatcher             *K8sPodWatcher
	k8sCiliumNodeWatcher      *K8sCiliumNodeWatcher
	k8sEndpointsWatcher       *K8sEndpointsWatcher
	k8sCiliumEndpointsWatcher *K8sCiliumEndpointsWatcher

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *synced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *synced.APIGroups

	cfg WatcherConfiguration

	// kcfg represents whether the KVStore is enabled or not.
	kcfg interface{ IsEnabled() bool }
}

func newWatcher(
	logger *slog.Logger,
	resourceGroupsFn func(logger *slog.Logger, cfg WatcherConfiguration) (resourceGroups, waitForCachesOnly []string),
	clientset client.Clientset,
	k8sPodWatcher *K8sPodWatcher,
	k8sCiliumNodeWatcher *K8sCiliumNodeWatcher,
	k8sEndpointsWatcher *K8sEndpointsWatcher,
	k8sCiliumEndpointsWatcher *K8sCiliumEndpointsWatcher,
	k8sEventReporter *K8sEventReporter,
	k8sResourceSynced *synced.Resources,
	k8sAPIGroups *synced.APIGroups,
	cfg WatcherConfiguration,
	kcfg interface{ IsEnabled() bool },
) *K8sWatcher {
	return &K8sWatcher{
		logger:                    logger,
		resourceGroupsFn:          resourceGroupsFn,
		clientset:                 clientset,
		k8sEventReporter:          k8sEventReporter,
		k8sPodWatcher:             k8sPodWatcher,
		k8sCiliumNodeWatcher:      k8sCiliumNodeWatcher,
		k8sEndpointsWatcher:       k8sEndpointsWatcher,
		k8sCiliumEndpointsWatcher: k8sCiliumEndpointsWatcher,
		k8sResourceSynced:         k8sResourceSynced,
		k8sAPIGroups:              k8sAPIGroups,
		cfg:                       cfg,
		kcfg:                      kcfg,
	}
}

// WaitForCacheSync blocks until the given resources have been synchronized from k8s.  Note that if
// the controller for a resource has not been started, the wait for that resource returns
// immediately. If it is required that the resource exists and is actually synchronized, the caller
// must ensure the controller for that resource has been started before calling
// WaitForCacheSync. For most resources this can be done by receiving from controllersStarted
// channel (<-k.controllersStarted), which is closed after most watchers have been started.
func (k *K8sWatcher) WaitForCacheSync(resourceNames ...string) {
	k.k8sResourceSynced.WaitForCacheSync(resourceNames...)
}

func (k *K8sWatcher) GetAPIGroups() []string {
	return k.k8sAPIGroups.GetGroups()
}

type watcherKind int

const (
	// skip causes watcher to not be started.
	skip watcherKind = iota

	// start causes watcher to be started as soon as possible.
	start

	// waitOnly will not start a watcher for this resource, but cause us to
	// wait for an external go routine to initialize it
	waitOnly
)

type watcherInfo struct {
	kind  watcherKind
	group string
}

var ciliumResourceToGroupMapping = map[string]watcherInfo{
	synced.CRDResourceName(cilium_v2.CNPName):           {waitOnly, k8sAPIGroupCiliumNetworkPolicyV2},            // Handled in pkg/policy/k8s/
	synced.CRDResourceName(cilium_v2.CCNPName):          {waitOnly, k8sAPIGroupCiliumClusterwideNetworkPolicyV2}, // Handled in pkg/policy/k8s/
	synced.CRDResourceName(cilium_v2.CEPName):           {start, k8sAPIGroupCiliumEndpointV2},                    // ipcache
	synced.CRDResourceName(cilium_v2.CNName):            {start, k8sAPIGroupCiliumNodeV2},
	synced.CRDResourceName(cilium_v2.CIDName):           {skip, ""},                                     // Handled in pkg/k8s/identitybackend/
	synced.CRDResourceName(cilium_v2.CLRPName):          {skip, k8sAPIGroupCiliumLocalRedirectPolicyV2}, // Handled in pkg/loadbalacer/redirectpolicy
	synced.CRDResourceName(cilium_v2.CEGPName):          {skip, ""},                                     // Handled via Resource[T].
	synced.CRDResourceName(v2alpha1.CESName):            {start, k8sAPIGroupCiliumEndpointSliceV2Alpha1},
	synced.CRDResourceName(cilium_v2.CCECName):          {skip, ""}, // Handled in pkg/ciliumenvoyconfig/
	synced.CRDResourceName(cilium_v2.CECName):           {skip, ""}, // Handled in pkg/ciliumenvoyconfig/
	synced.CRDResourceName(v2alpha1.BGPPName):           {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPCCName):          {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPAName):           {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPPCName):          {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPNCName):          {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPNCOName):         {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.LBIPPoolName):       {skip, ""}, // Handled in LB IPAM
	synced.CRDResourceName(v2alpha1.CNCName):            {skip, ""}, // Handled by init directly
	synced.CRDResourceName(cilium_v2.CCGName):           {waitOnly, k8sAPIGroupCiliumCIDRGroupV2},
	synced.CRDResourceName(v2alpha1.L2AnnouncementName): {skip, ""}, // Handled by L2 announcement directly
	synced.CRDResourceName(v2alpha1.CPIPName):           {skip, ""}, // Handled by multi-pool IPAM allocator
}

func GetGroupsForCiliumResources(logger *slog.Logger, ciliumResources []string) ([]string, []string) {
	ciliumGroups := make([]string, 0, len(ciliumResources))
	waitOnlyList := make([]string, 0)

	for _, r := range ciliumResources {
		groupInfo, ok := ciliumResourceToGroupMapping[r]
		if !ok {
			logging.Fatal(logger, fmt.Sprintf("Unknown resource %s. Please update pkg/k8s/watchers to understand this type.", r))
		}
		switch groupInfo.kind {
		case skip:
			continue
		case start:
			ciliumGroups = append(ciliumGroups, groupInfo.group)
		case waitOnly:
			waitOnlyList = append(waitOnlyList, groupInfo.group)
		}
	}

	return ciliumGroups, waitOnlyList
}

// InitK8sSubsystem takes a channel for which it will be closed when all
// caches essential for daemon are synchronized.
// It initializes the K8s subsystem and starts the watchers for the resources
// that the daemon is interested in.
// The cachesSynced channel is closed when all caches are synchronized.
// To be called after WaitForCRDsToRegister() so that all needed CRDs have
// already been registered.
func (k *K8sWatcher) InitK8sSubsystem(ctx context.Context, cachesSynced chan struct{}) {
	resources, cachesOnly := k.resourceGroupsFn(k.logger, k.cfg)

	k.logger.Info("Enabling k8s event listener")
	k.enableK8sWatchers(ctx, resources)
	close(k.k8sPodWatcher.controllersStarted)

	go func() {
		k.logger.Info("Waiting until all pre-existing resources have been received")
		allResources := append(resources, cachesOnly...)
		if err := k.k8sResourceSynced.WaitForCacheSyncWithTimeout(ctx, option.Config.K8sSyncTimeout, allResources...); err != nil {
			logging.Fatal(k.logger, "Timed out waiting for pre-existing resources to be received; exiting", logfields.Error, err)
		}
		close(cachesSynced)
	}()
}

// WatcherConfiguration is the required configuration for enableK8sWatchers
type WatcherConfiguration interface {
	// K8sNetworkPolicyEnabled returns true if cilium agent needs to support K8s NetworkPolicy
	K8sNetworkPolicyEnabled() bool
}

// enableK8sWatchers starts watchers for given resources.
func (k *K8sWatcher) enableK8sWatchers(ctx context.Context, resourceNames []string) {
	if !k.clientset.IsEnabled() {
		k.logger.Debug("Not enabling k8s event listener because k8s is not enabled")
		return
	}

	for _, r := range resourceNames {
		switch r {
		// Core Cilium
		case resources.K8sAPIGroupPodV1Core:
			k.k8sPodWatcher.podsInit(ctx)
		case k8sAPIGroupCiliumNodeV2:
			if !k.kcfg.IsEnabled() {
				k.k8sCiliumNodeWatcher.ciliumNodeInit(ctx)
			}
		case resources.K8sAPIGroupEndpointSliceOrEndpoint:
			k.k8sEndpointsWatcher.endpointsInit()
		case k8sAPIGroupCiliumEndpointV2:
			if !k.kcfg.IsEnabled() {
				k.k8sCiliumEndpointsWatcher.initCiliumEndpointOrSlices(ctx)
			}
		case k8sAPIGroupCiliumEndpointSliceV2Alpha1:
			// no-op; handled in k8sAPIGroupCiliumEndpointV2
		default:
			logging.Fatal(k.logger,
				"Not listening for Kubernetes resource updates for unhandled type",
				logfields.Resource, r,
			)
		}
	}
}

func (k *K8sWatcher) StopWatcher() {
	k.k8sEndpointsWatcher.stopWatcher()
}

// K8sEventProcessed is called to do metrics accounting for each processed
// Kubernetes event
func (k *K8sWatcher) K8sEventProcessed(scope, action string, status bool) {
	k.k8sEventReporter.K8sEventProcessed(scope, action, status)
}

// K8sEventReceived does metric accounting for each received Kubernetes event, as well
// as notifying of events for k8s resources synced.
func (k *K8sWatcher) K8sEventReceived(apiResourceName, scope, action string, valid, equal bool) {
	k.k8sEventReporter.K8sEventReceived(apiResourceName, scope, action, valid, equal)
}

// GetCachedPod returns a pod from the local store.
func (k *K8sWatcher) GetCachedPod(namespace, name string) (*slim_corev1.Pod, error) {
	return k.k8sPodWatcher.GetCachedPod(namespace, name)
}

// GetK8sCiliumEndpointsWatcher returns CEP watcher
func (k *K8sWatcher) GetK8sCiliumEndpointsWatcher() *K8sCiliumEndpointsWatcher {
	return k.k8sCiliumEndpointsWatcher
}

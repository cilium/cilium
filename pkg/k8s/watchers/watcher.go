// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/safetime"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const (
	k8sAPIGroupNamespaceV1Core                  = "core/v1::Namespace"
	K8sAPIGroupServiceV1Core                    = "core/v1::Service"
	k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
	k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
	k8sAPIGroupCiliumCIDRGroupV2Alpha1          = "cilium/v2alpha1::CiliumCIDRGroup"
	k8sAPIGroupCiliumNodeV2                     = "cilium/v2::CiliumNode"
	k8sAPIGroupCiliumEndpointV2                 = "cilium/v2::CiliumEndpoint"
	k8sAPIGroupCiliumLocalRedirectPolicyV2      = "cilium/v2::CiliumLocalRedirectPolicy"
	k8sAPIGroupCiliumEndpointSliceV2Alpha1      = "cilium/v2alpha1::CiliumEndpointSlice"

	metricCLRP = "CiliumLocalRedirectPolicy"
	metricPod  = "Pod"
)

func init() {
	// Replace error handler with our own
	runtime.ErrorHandlers = []func(error){
		k8s.K8sErrorHandler,
	}
}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s-watcher")

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
	TriggerPolicyUpdates(force bool, reason string)
}

type svcManager interface {
	DeleteService(frontend loadbalancer.L3n4Addr) (bool, error)
	GetDeepCopyServiceByFrontend(frontend loadbalancer.L3n4Addr) (*loadbalancer.SVC, bool)
	UpsertService(*loadbalancer.SVC) (bool, loadbalancer.ID, error)
}

type redirectPolicyManager interface {
	AddRedirectPolicy(config redirectpolicy.LRPConfig) (bool, error)
	DeleteRedirectPolicy(config redirectpolicy.LRPConfig) error
	OnAddService(svcID k8s.ServiceID)
	OnDeleteService(svcID k8s.ServiceID)
	OnUpdatePod(pod *slim_corev1.Pod, needsReassign bool, ready bool)
	OnDeletePod(pod *slim_corev1.Pod)
	OnAddPod(pod *slim_corev1.Pod)
}

type bgpSpeakerManager interface {
	OnUpdateService(svc *slim_corev1.Service) error
	OnDeleteService(svc *slim_corev1.Service) error

	OnUpdateEndpoints(eps *k8s.Endpoints) error
}

type cgroupManager interface {
	OnAddPod(pod *slim_corev1.Pod)
	OnUpdatePod(oldPod, newPod *slim_corev1.Pod)
	OnDeletePod(pod *slim_corev1.Pod)
}

type ipcacheManager interface {
	// GH-21142: Re-evaluate the need for these APIs
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (namedPortsChanged bool, err error)
	LookupByIP(IP string) (ipcache.Identity, bool)
	Delete(IP string, source source.Source) (namedPortsChanged bool)

	UpsertLabels(prefix netip.Prefix, lbls labels.Labels, src source.Source, resource ipcacheTypes.ResourceID)
	RemoveLabelsExcluded(lbls labels.Labels, toExclude map[netip.Prefix]struct{}, resource ipcacheTypes.ResourceID)
	DeleteOnMetadataMatch(IP string, source source.Source, namespace, name string) (namedPortsChanged bool)
}

type K8sWatcher struct {
	resourceGroupsFn func(cfg WatcherConfiguration) (resourceGroups, waitForCachesOnly []string)

	clientset client.Clientset

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *synced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *synced.APIGroups

	// K8sSvcCache is a cache of all Kubernetes services and endpoints
	K8sSvcCache *k8s.ServiceCache

	endpointManager endpointManager

	nodeManager           nodeManager
	policyManager         policyManager
	svcManager            svcManager
	redirectPolicyManager redirectPolicyManager
	bgpSpeakerManager     bgpSpeakerManager
	ipcache               ipcacheManager
	cgroupManager         cgroupManager

	bandwidthManager datapath.BandwidthManager

	// controllersStarted is a channel that is closed when all watchers that do not depend on
	// local node configuration have been started
	controllersStarted chan struct{}

	stop chan struct{}

	podStoreMU lock.RWMutex
	podStore   cache.Store
	// podStoreSet is a channel that is closed when the podStore cache is
	// variable is written for the first time.
	podStoreSet  chan struct{}
	podStoreOnce sync.Once

	ciliumNodeStore atomic.Pointer[resource.Store[*cilium_v2.CiliumNode]]

	cfg WatcherConfiguration

	resources agentK8s.Resources

	db        *statedb.DB
	nodeAddrs statedb.Table[datapathTables.NodeAddress]
}

func NewK8sWatcher(
	clientset client.Clientset,
	k8sResourceSynced *synced.Resources,
	k8sAPIGroups *synced.APIGroups,
	endpointManager endpointManager,
	nodeManager nodeManager,
	policyManager policyManager,
	svcManager svcManager,
	redirectPolicyManager redirectPolicyManager,
	bgpSpeakerManager bgpSpeakerManager,
	cfg WatcherConfiguration,
	ipcache ipcacheManager,
	cgroupManager cgroupManager,
	resources agentK8s.Resources,
	serviceCache *k8s.ServiceCache,
	bandwidthManager datapath.BandwidthManager,
	db *statedb.DB,
	nodeAddrs statedb.Table[datapathTables.NodeAddress],
) *K8sWatcher {
	return &K8sWatcher{
		resourceGroupsFn:      resourceGroups,
		db:                    db,
		clientset:             clientset,
		k8sResourceSynced:     k8sResourceSynced,
		k8sAPIGroups:          k8sAPIGroups,
		K8sSvcCache:           serviceCache,
		endpointManager:       endpointManager,
		nodeManager:           nodeManager,
		policyManager:         policyManager,
		svcManager:            svcManager,
		ipcache:               ipcache,
		controllersStarted:    make(chan struct{}),
		stop:                  make(chan struct{}),
		podStoreSet:           make(chan struct{}),
		redirectPolicyManager: redirectPolicyManager,
		bgpSpeakerManager:     bgpSpeakerManager,
		cgroupManager:         cgroupManager,
		bandwidthManager:      bandwidthManager,
		cfg:                   cfg,
		resources:             resources,
		nodeAddrs:             nodeAddrs,
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

// WaitForCRDsToRegister will wait for the Cilium Operator to register the CRDs
// with the apiserver. This step is required before launching the full K8s
// watcher, as those resource controllers need the resources to be registered
// with K8s first.
func (k *K8sWatcher) WaitForCRDsToRegister(ctx context.Context) error {
	return synced.SyncCRDs(ctx, k.clientset, synced.AgentCRDResourceNames(), k.k8sResourceSynced, k.k8sAPIGroups)
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
	synced.CRDResourceName(cilium_v2.CIDName):           {skip, ""}, // Handled in pkg/k8s/identitybackend/
	synced.CRDResourceName(cilium_v2.CLRPName):          {start, k8sAPIGroupCiliumLocalRedirectPolicyV2},
	synced.CRDResourceName(cilium_v2.CEWName):           {skip, ""}, // Handled in clustermesh-apiserver/
	synced.CRDResourceName(cilium_v2.CEGPName):          {skip, ""}, // Handled via Resource[T].
	synced.CRDResourceName(v2alpha1.CESName):            {start, k8sAPIGroupCiliumEndpointSliceV2Alpha1},
	synced.CRDResourceName(cilium_v2.CCECName):          {skip, ""}, // Handled via CiliumEnvoyConfig watcher via Resource[T]
	synced.CRDResourceName(cilium_v2.CECName):           {skip, ""}, // Handled via CiliumEnvoyConfig watcher via Resource[T]
	synced.CRDResourceName(v2alpha1.BGPPName):           {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPCCName):          {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPAName):           {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPPCName):          {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPNCName):          {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPNCOName):         {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.LBIPPoolName):       {skip, ""}, // Handled in LB IPAM
	synced.CRDResourceName(v2alpha1.CNCName):            {skip, ""}, // Handled by init directly
	synced.CRDResourceName(v2alpha1.CCGName):            {waitOnly, k8sAPIGroupCiliumCIDRGroupV2Alpha1},
	synced.CRDResourceName(v2alpha1.L2AnnouncementName): {skip, ""}, // Handled by L2 announcement directly
	synced.CRDResourceName(v2alpha1.CPIPName):           {skip, ""}, // Handled by multi-pool IPAM allocator
}

// resourceGroups are all of the core Kubernetes and Cilium resource groups
// which the Cilium agent watches to implement CNI functionality.
func resourceGroups(cfg WatcherConfiguration) (resourceGroups, waitForCachesOnly []string) {
	k8sGroups := []string{
		// To perform the service translation and have the BPF LB datapath
		// with the right service -> backend (k8s endpoints) translation.
		K8sAPIGroupServiceV1Core,

		// Namespaces can contain labels which are essential for
		// endpoints being restored to have the right identity.
		k8sAPIGroupNamespaceV1Core,
		// Pods can contain labels which are essential for endpoints
		// being restored to have the right identity.
		resources.K8sAPIGroupPodV1Core,
		// To perform the service translation and have the BPF LB datapath
		// with the right service -> backend (k8s endpoints) translation.
		resources.K8sAPIGroupEndpointSliceOrEndpoint,
	}

	if cfg.K8sNetworkPolicyEnabled() {
		// When the flag is set,
		// We need all network policies in place before restoring to
		// make sure we are enforcing the correct policies for each
		// endpoint before restarting.
		waitForCachesOnly = append(waitForCachesOnly, k8sAPIGroupNetworkingV1Core)
	}

	ciliumResources := synced.AgentCRDResourceNames()
	ciliumGroups := make([]string, 0, len(ciliumResources))
	for _, r := range ciliumResources {
		groupInfo, ok := ciliumResourceToGroupMapping[r]
		if !ok {
			log.Fatalf("Unknown resource %s. Please update pkg/k8s/watchers to understand this type.", r)
		}
		switch groupInfo.kind {
		case skip:
			continue
		case start:
			ciliumGroups = append(ciliumGroups, groupInfo.group)
		case waitOnly:
			waitForCachesOnly = append(waitForCachesOnly, groupInfo.group)
		}
	}

	return append(k8sGroups, ciliumGroups...), waitForCachesOnly
}

// InitK8sSubsystem takes a channel for which it will be closed when all
// caches essential for daemon are synchronized.
// It initializes the K8s subsystem and starts the watchers for the resources
// that the daemon is interested in.
// The cachesSynced channel is closed when all caches are synchronized.
// To be called after WaitForCRDsToRegister() so that all needed CRDs have
// already been registered.
func (k *K8sWatcher) InitK8sSubsystem(ctx context.Context, cachesSynced chan struct{}) {
	resources, cachesOnly := k.resourceGroupsFn(k.cfg)

	log.Info("Enabling k8s event listener")
	k.enableK8sWatchers(ctx, resources)
	close(k.controllersStarted)

	go func() {
		log.Info("Waiting until all pre-existing resources have been received")
		allResources := append(resources, cachesOnly...)
		if err := k.k8sResourceSynced.WaitForCacheSyncWithTimeout(option.Config.K8sSyncTimeout, allResources...); err != nil {
			log.WithError(err).Fatal("Timed out waiting for pre-existing resources to be received; exiting")
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
		log.Debug("Not enabling k8s event listener because k8s is not enabled")
		return
	}
	asyncControllers := &sync.WaitGroup{}

	for _, r := range resourceNames {
		switch r {
		// Core Cilium
		case resources.K8sAPIGroupPodV1Core:
			asyncControllers.Add(1)
			go k.podsInit(k.clientset.Slim(), asyncControllers)
		case k8sAPIGroupNamespaceV1Core:
			k.namespacesInit()
		case k8sAPIGroupCiliumNodeV2:
			asyncControllers.Add(1)
			go k.ciliumNodeInit(ctx, asyncControllers)
		case resources.K8sAPIGroupServiceV1Core:
			k.servicesInit()
		case resources.K8sAPIGroupEndpointSliceOrEndpoint:
			k.endpointsInit()
		case k8sAPIGroupCiliumEndpointV2:
			k.initCiliumEndpointOrSlices(ctx, asyncControllers)
		case k8sAPIGroupCiliumEndpointSliceV2Alpha1:
			// no-op; handled in k8sAPIGroupCiliumEndpointV2
		case k8sAPIGroupCiliumLocalRedirectPolicyV2:
			k.ciliumLocalRedirectPolicyInit(k.clientset)
		default:
			log.WithFields(logrus.Fields{
				logfields.Resource: r,
			}).Fatal("Not listening for Kubernetes resource updates for unhandled type")
		}
	}

	asyncControllers.Wait()
}

// K8sEventProcessed is called to do metrics accounting for each processed
// Kubernetes event
func (k *K8sWatcher) K8sEventProcessed(scope, action string, status bool) {
	result := "success"
	if !status {
		result = "failed"
	}

	metrics.KubernetesEventProcessed.WithLabelValues(scope, action, result).Inc()
}

// K8sEventReceived does metric accounting for each received Kubernetes event, as well
// as notifying of events for k8s resources synced.
func (k *K8sWatcher) K8sEventReceived(apiResourceName, scope, action string, valid, equal bool) {
	k8smetrics.LastInteraction.Reset()

	metrics.EventTS.WithLabelValues(metrics.LabelEventSourceK8s, scope, action).SetToCurrentTime()
	validStr := strconv.FormatBool(valid)
	equalStr := strconv.FormatBool(equal)
	metrics.KubernetesEventReceived.WithLabelValues(scope, action, validStr, equalStr).Inc()

	k.k8sResourceSynced.SetEventTimestamp(apiResourceName)
}

// K8sServiceEventProcessed is called to do metrics accounting the duration to program the service.
func (k *K8sWatcher) K8sServiceEventProcessed(action string, startTime time.Time) {
	duration, _ := safetime.TimeSinceSafe(startTime, log)
	metrics.ServiceImplementationDelay.WithLabelValues(action).Observe(duration.Seconds())
}

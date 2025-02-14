// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/runtime"

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
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/source"
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
	k8sAPIGroupCiliumEnvoyConfigV2              = "cilium/v2::CiliumEnvoyConfig"
	k8sAPIGroupCiliumClusterwideEnvoyConfigV2   = "cilium/v2::CiliumClusterwideEnvoyConfig"

	metricCLRP = "CiliumLocalRedirectPolicy"
	metricPod  = "Pod"
)

func init() {
	// Replace error handler with our own
	runtime.ErrorHandlers = []runtime.ErrorHandler{
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
	TriggerPolicyUpdates(reason string)
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
	EnsureService(svcID k8s.ServiceID) (bool, error)
	OnDeleteService(svcID k8s.ServiceID)
	OnUpdatePod(pod *slim_corev1.Pod, needsReassign bool, ready bool)
	OnDeletePod(pod *slim_corev1.Pod)
	OnAddPod(pod *slim_corev1.Pod)
}

type cgroupManager interface {
	OnAddPod(pod *slim_corev1.Pod)
	OnUpdatePod(oldPod, newPod *slim_corev1.Pod)
	OnDeletePod(pod *slim_corev1.Pod)
}

type CacheAccessK8SWatcher interface {
	GetCachedNamespace(namespace string) (*slim_corev1.Namespace, error)
	GetCachedPod(namespace, name string) (*slim_corev1.Pod, error)
}

type ipcacheManager interface {
	// GH-21142: Re-evaluate the need for these APIs
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (namedPortsChanged bool, err error)
	LookupByIP(IP string) (ipcache.Identity, bool)
	Delete(IP string, source source.Source) (namedPortsChanged bool)

	UpsertLabels(prefix netip.Prefix, lbls labels.Labels, src source.Source, resource ipcacheTypes.ResourceID)
	RemoveLabels(prefix netip.Prefix, lbls labels.Labels, resource ipcacheTypes.ResourceID)
	RemoveLabelsExcluded(lbls labels.Labels, toExclude map[netip.Prefix]struct{}, resource ipcacheTypes.ResourceID)
	DeleteOnMetadataMatch(IP string, source source.Source, namespace, name string) (namedPortsChanged bool)
}

type K8sWatcher struct {
	resourceGroupsFn func(cfg WatcherConfiguration) (resourceGroups, waitForCachesOnly []string)

	clientset client.Clientset

	k8sEventReporter          *K8sEventReporter
	k8sPodWatcher             *K8sPodWatcher
	k8sCiliumNodeWatcher      *K8sCiliumNodeWatcher
	k8sNamespaceWatcher       *K8sNamespaceWatcher
	k8sServiceWatcher         *K8sServiceWatcher
	k8sEndpointsWatcher       *K8sEndpointsWatcher
	k8sCiliumLRPWatcher       *K8sCiliumLRPWatcher
	k8sCiliumEndpointsWatcher *K8sCiliumEndpointsWatcher

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *synced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *synced.APIGroups

	cfg WatcherConfiguration
}

func newWatcher(
	clientset client.Clientset,
	k8sPodWatcher *K8sPodWatcher,
	k8sCiliumNodeWatcher *K8sCiliumNodeWatcher,
	k8sNamespaceWatcher *K8sNamespaceWatcher,
	k8sServiceWatcher *K8sServiceWatcher,
	k8sEndpointsWatcher *K8sEndpointsWatcher,
	k8sCiliumLRPWatcher *K8sCiliumLRPWatcher,
	k8sCiliumEndpointsWatcher *K8sCiliumEndpointsWatcher,
	k8sEventReporter *K8sEventReporter,
	k8sResourceSynced *synced.Resources,
	k8sAPIGroups *synced.APIGroups,
	cfg WatcherConfiguration,
) *K8sWatcher {
	return &K8sWatcher{
		resourceGroupsFn:          resourceGroups,
		clientset:                 clientset,
		k8sEventReporter:          k8sEventReporter,
		k8sPodWatcher:             k8sPodWatcher,
		k8sCiliumNodeWatcher:      k8sCiliumNodeWatcher,
		k8sNamespaceWatcher:       k8sNamespaceWatcher,
		k8sServiceWatcher:         k8sServiceWatcher,
		k8sEndpointsWatcher:       k8sEndpointsWatcher,
		k8sCiliumLRPWatcher:       k8sCiliumLRPWatcher,
		k8sCiliumEndpointsWatcher: k8sCiliumEndpointsWatcher,
		k8sResourceSynced:         k8sResourceSynced,
		k8sAPIGroups:              k8sAPIGroups,
		cfg:                       cfg,
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
	synced.CRDResourceName(cilium_v2.CCECName):          {waitOnly, k8sAPIGroupCiliumClusterwideEnvoyConfigV2}, // Handled in pkg/ciliumenvoyconfig/
	synced.CRDResourceName(cilium_v2.CECName):           {waitOnly, k8sAPIGroupCiliumEnvoyConfigV2},            // Handled in pkg/ciliumenvoyconfig/
	synced.CRDResourceName(v2alpha1.BGPPName):           {skip, ""},                                            // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPCCName):          {skip, ""},                                            // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPAName):           {skip, ""},                                            // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPPCName):          {skip, ""},                                            // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPNCName):          {skip, ""},                                            // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPNCOName):         {skip, ""},                                            // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.LBIPPoolName):       {skip, ""},                                            // Handled in LB IPAM
	synced.CRDResourceName(v2alpha1.CNCName):            {skip, ""},                                            // Handled by init directly
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
	k._initK8sSubsystem(ctx, cachesSynced, resources, cachesOnly)
}

// InitK8sSubsystemWithResources takes a channel for which it will be closed when all
// the resources are synchronized. Different from InitK8sSubsystem, this function
// allows watcher to only sync the resources that are passed in.
func (k *K8sWatcher) InitK8sSubsystemWithResources(ctx context.Context, cachesSynced chan struct{}, resources []string) {
	k._initK8sSubsystem(ctx, cachesSynced, resources, nil)
}

// _initK8sSubsystem is a helper function to initialize the K8s subsystem.
func (k *K8sWatcher) _initK8sSubsystem(ctx context.Context, cachesSynced chan struct{}, resources []string, cachesOnly []string) {
	log.Info("Enabling k8s event listener")
	k.enableK8sWatchers(ctx, resources)
	close(k.k8sPodWatcher.controllersStarted)

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

	// KVstoreEnabledWithoutPodNetworkSupport returns whether Cilium is configured to connect
	// to an external KVStore, and the support for running it in pod network is disabled.
	// In this case, we don't need to start the CiliumNode and CiliumEndpoint watchers at
	// all, given that the CRD to kvstore handover logic is not required.
	KVstoreEnabledWithoutPodNetworkSupport() bool
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
			go k.k8sPodWatcher.podsInit(asyncControllers)
		case k8sAPIGroupNamespaceV1Core:
			k.k8sNamespaceWatcher.namespacesInit()
		case k8sAPIGroupCiliumNodeV2:
			if !k.cfg.KVstoreEnabledWithoutPodNetworkSupport() {
				asyncControllers.Add(1)
				go k.k8sCiliumNodeWatcher.ciliumNodeInit(ctx, asyncControllers)
			}
		case resources.K8sAPIGroupServiceV1Core:
			k.k8sServiceWatcher.servicesInit()
		case resources.K8sAPIGroupEndpointSliceOrEndpoint:
			k.k8sEndpointsWatcher.endpointsInit()
		case k8sAPIGroupCiliumEndpointV2:
			if !k.cfg.KVstoreEnabledWithoutPodNetworkSupport() {
				k.k8sCiliumEndpointsWatcher.initCiliumEndpointOrSlices(ctx, asyncControllers)
			}
		case k8sAPIGroupCiliumEndpointSliceV2Alpha1:
			// no-op; handled in k8sAPIGroupCiliumEndpointV2
		case k8sAPIGroupCiliumLocalRedirectPolicyV2:
			k.k8sCiliumLRPWatcher.ciliumLocalRedirectPolicyInit()
		default:
			log.WithFields(logrus.Fields{
				logfields.Resource: r,
			}).Fatal("Not listening for Kubernetes resource updates for unhandled type")
		}
	}

	asyncControllers.Wait()
}

func (k *K8sWatcher) StopWatcher() {
	k.k8sNamespaceWatcher.stopWatcher()
	k.k8sServiceWatcher.stopWatcher()
	k.k8sEndpointsWatcher.stopWatcher()
	k.k8sCiliumLRPWatcher.stopWatcher()
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

// GetCachedNamespace returns a namespace from the local store.
func (k *K8sWatcher) GetCachedNamespace(namespace string) (*slim_corev1.Namespace, error) {
	return k.k8sNamespaceWatcher.GetCachedNamespace(namespace)
}

func (k *K8sWatcher) RunK8sServiceHandler() {
	k.k8sServiceWatcher.RunK8sServiceHandler()
}

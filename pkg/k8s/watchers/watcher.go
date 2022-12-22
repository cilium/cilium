// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	k8s_metrics "k8s.io/client-go/tools/metrics"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/egressgateway"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discover_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discover_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	serviceCache "github.com/cilium/cilium/pkg/service/cache"
	"github.com/cilium/cilium/pkg/source"
)

const (
	k8sAPIGroupNodeV1Core                       = "core/v1::Node"
	k8sAPIGroupNamespaceV1Core                  = "core/v1::Namespace"
	K8sAPIGroupServiceV1Core                    = "core/v1::Service"
	k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
	k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
	k8sAPIGroupCiliumNodeV2                     = "cilium/v2::CiliumNode"
	k8sAPIGroupCiliumEndpointV2                 = "cilium/v2::CiliumEndpoint"
	k8sAPIGroupCiliumLocalRedirectPolicyV2      = "cilium/v2::CiliumLocalRedirectPolicy"
	k8sAPIGroupCiliumEgressGatewayPolicyV2      = "cilium/v2::CiliumEgressGatewayPolicy"
	k8sAPIGroupCiliumEgressNATPolicyV2          = "cilium/v2::CiliumEgressNATPolicy"
	k8sAPIGroupCiliumEndpointSliceV2Alpha1      = "cilium/v2alpha1::CiliumEndpointSlice"
	k8sAPIGroupCiliumClusterwideEnvoyConfigV2   = "cilium/v2::CiliumClusterwideEnvoyConfig"
	k8sAPIGroupCiliumEnvoyConfigV2              = "cilium/v2::CiliumEnvoyConfig"

	metricKNP            = "NetworkPolicy"
	metricNS             = "Namespace"
	metricSecret         = "Secret"
	metricCiliumNode     = "CiliumNode"
	metricCiliumEndpoint = "CiliumEndpoint"
	metricCLRP           = "CiliumLocalRedirectPolicy"
	metricCEGP           = "CiliumEgressGatewayPolicy"
	metricCENP           = "CiliumEgressNATPolicy"
	metricCCEC           = "CiliumClusterwideEnvoyConfig"
	metricCEC            = "CiliumEnvoyConfig"
	metricPod            = "Pod"
	metricNode           = "Node"
)

func init() {
	// Replace error handler with our own
	runtime.ErrorHandlers = []func(error){
		k8s.K8sErrorHandler,
	}

	k8s_metrics.Register(k8s_metrics.RegisterOpts{
		ClientCertExpiry:      nil,
		ClientCertRotationAge: nil,
		RequestLatency:        &k8sMetrics{},
		RateLimiterLatency:    nil,
		RequestResult:         &k8sMetrics{},
	})
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s-watcher")

	k8sCM = controller.NewManager()

	importMetadataCache = ruleImportMetadataCache{
		ruleImportMetadataMap: make(map[string]policyImportMetadata),
	}
)

type endpointManager interface {
	GetEndpoints() []*endpoint.Endpoint
	GetHostEndpoint() *endpoint.Endpoint
	LookupPodName(string) *endpoint.Endpoint
	WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error
	UpdatePolicyMaps(context.Context, *sync.WaitGroup) *sync.WaitGroup
}

type nodeDiscoverManager interface {
	WaitForLocalNodeInit()
	NodeDeleted(n nodeTypes.Node)
	NodeUpdated(n nodeTypes.Node)
	ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration
}

type policyManager interface {
	TriggerPolicyUpdates(force bool, reason string)
	PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	PolicyDelete(labels labels.LabelArray) (newRev uint64, err error)
}

type policyRepository interface {
	GetSelectorCache() *policy.SelectorCache
	TranslateRules(translator policy.Translator) (*policy.TranslationResult, error)
}

/*
type svcManager interface {
	DeleteService(frontend loadbalancer.L3n4Addr) (bool, error)
	UpsertService(*loadbalancer.SVC) (bool, loadbalancer.ID, error)
	RegisterL7LBService(serviceName, resourceName loadbalancer.ServiceName, ports []string, proxyPort uint16) error
	RegisterL7LBServiceBackendSync(serviceName, resourceName loadbalancer.ServiceName, ports []string) error
	RemoveL7LBService(serviceName, resourceName loadbalancer.ServiceName) error
}*/

/*
type redirectPolicyManager interface {
	AddRedirectPolicy(config redirectpolicy.LRPConfig) (bool, error)
	DeleteRedirectPolicy(config redirectpolicy.LRPConfig) error
	OnAddService(svcID k8s.ServiceID)
	OnDeleteService(svcID k8s.ServiceID)
	OnUpdatePod(pod *slim_corev1.Pod, needsReassign bool, ready bool)
	OnDeletePod(pod *slim_corev1.Pod)
	OnAddPod(pod *slim_corev1.Pod)
}*/

type bgpSpeakerManager interface {
	OnUpdateService(svc *slim_corev1.Service) error
	OnDeleteService(svc *slim_corev1.Service) error

	OnUpdateEndpoints(eps *slim_corev1.Endpoints) error
	OnUpdateEndpointSliceV1(eps *slim_discover_v1.EndpointSlice) error
	OnUpdateEndpointSliceV1Beta1(eps *slim_discover_v1beta1.EndpointSlice) error
}
type egressGatewayManager interface {
	OnAddEgressPolicy(config egressgateway.PolicyConfig)
	OnDeleteEgressPolicy(configID types.NamespacedName)
	OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint)
	OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint)
	OnUpdateNode(node nodeTypes.Node)
	OnDeleteNode(node nodeTypes.Node)
}

type envoyConfigManager interface {
	UpsertEnvoyResources(context.Context, envoy.Resources, envoy.PortAllocator) error
	UpdateEnvoyResources(ctx context.Context, old, new envoy.Resources, portAllocator envoy.PortAllocator) error
	DeleteEnvoyResources(context.Context, envoy.Resources, envoy.PortAllocator) error

	// envoy.PortAllocator
	AllocateProxyPort(name string, ingress bool) (uint16, error)
	AckProxyPort(ctx context.Context, name string) error
	ReleaseProxyPort(name string) error
}

type cgroupManager interface {
	OnAddPod(pod *slim_corev1.Pod)
	OnUpdatePod(oldPod, newPod *slim_corev1.Pod)
	OnDeletePod(pod *slim_corev1.Pod)
}

type ipcacheManager interface {
	AllocateCIDRs(prefixes []netip.Prefix, oldNIDs []identity.NumericIdentity, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity) ([]*identity.Identity, error)
	ReleaseCIDRIdentitiesByCIDR(prefixes []netip.Prefix)

	// GH-21142: Re-evaluate the need for these APIs
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (namedPortsChanged bool, err error)
	LookupByIP(IP string) (ipcache.Identity, bool)
	Delete(IP string, source source.Source) (namedPortsChanged bool)

	UpsertLabels(prefix netip.Prefix, lbls labels.Labels, src source.Source, resource ipcacheTypes.ResourceID)
	RemoveLabelsExcluded(lbls labels.Labels, toExclude map[netip.Prefix]struct{}, resource ipcacheTypes.ResourceID)
	DeleteOnMetadataMatch(IP string, source source.Source, namespace, name string) (namedPortsChanged bool)
}

type K8sWatcher struct {
	clientset client.Clientset

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced synced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups synced.APIGroups

	// K8sSvcCache is a cache of all Kubernetes services and endpoints
	K8sSvcCache serviceCache.ServiceCache

	// NodeChain is the root of a notification chain for k8s Node events.
	// This NodeChain allows registration of subscriber.Node implementations.
	// On k8s Node events all registered subscriber.Node implementations will
	// have their event handling methods called in order of registration.
	NodeChain *subscriber.NodeChain

	// CiliumNodeChain is the root of a notification chain for CiliumNode events.
	// This CiliumNodeChain allows registration of subscriber.CiliumNode implementations.
	// On CiliumNode events all registered subscriber.CiliumNode implementations will
	// have their event handling methods called in order of registration.
	CiliumNodeChain *subscriber.CiliumNodeChain

	endpointManager endpointManager

	nodeDiscoverManager nodeDiscoverManager
	policyManager       policyManager
	policyRepository    policyRepository
	//svcHandle           service.ServiceHandle
	//redirectPolicyManager redirectPolicyManager
	bgpSpeakerManager    bgpSpeakerManager
	egressGatewayManager egressGatewayManager
	ipcache              ipcacheManager
	envoyConfigManager   envoyConfigManager
	cgroupManager        cgroupManager

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

	// nodesInitOnce is used to guarantee that only one function call of NodesInit is executed.
	nodesInitOnce sync.Once

	ciliumNodeStoreMU lock.RWMutex
	ciliumNodeStore   cache.Store

	ciliumEndpointIndexerMU lock.RWMutex
	ciliumEndpointIndexer   cache.Indexer

	ciliumEndpointSliceIndexerMU lock.RWMutex
	// note: this store only contains endpointslices referencing local endpoints.
	ciliumEndpointSliceIndexer cache.Indexer

	datapath datapath.Datapath

	networkpolicyStore cache.Store

	cfg WatcherConfiguration

	sharedResources k8s.SharedResources
}

func NewK8sWatcher(
	clientset client.Clientset,
	endpointManager endpointManager,
	nodeDiscoverManager nodeDiscoverManager,
	policyManager policyManager,
	policyRepository policyRepository,
	//svcManager service.ServiceManager,
	datapath datapath.Datapath,
	//redirectPolicyManager redirectPolicyManager,
	bgpSpeakerManager bgpSpeakerManager,
	egressGatewayManager egressGatewayManager,
	envoyConfigManager envoyConfigManager,
	cfg WatcherConfiguration,
	ipcache ipcacheManager,
	cgroupManager cgroupManager,
	sharedResources k8s.SharedResources,
	serviceCache serviceCache.ServiceCache,
) *K8sWatcher {
	return &K8sWatcher{
		clientset:           clientset,
		K8sSvcCache:         serviceCache,
		endpointManager:     endpointManager,
		nodeDiscoverManager: nodeDiscoverManager,
		policyManager:       policyManager,
		policyRepository:    policyRepository,
		//svcHandle:             svcManager.NewHandle("k8s-watcher"),
		ipcache:            ipcache,
		controllersStarted: make(chan struct{}),
		stop:               make(chan struct{}),
		podStoreSet:        make(chan struct{}),
		datapath:           datapath,
		//redirectPolicyManager: redirectPolicyManager,
		bgpSpeakerManager:    bgpSpeakerManager,
		egressGatewayManager: egressGatewayManager,
		cgroupManager:        cgroupManager,
		NodeChain:            subscriber.NewNodeChain(),
		CiliumNodeChain:      subscriber.NewCiliumNodeChain(),
		envoyConfigManager:   envoyConfigManager,
		cfg:                  cfg,
		sharedResources:      sharedResources,
	}
}

// k8sMetrics implements the LatencyMetric and ResultMetric interface from
// k8s client-go package
type k8sMetrics struct{}

func (*k8sMetrics) Observe(_ context.Context, verb string, u url.URL, latency time.Duration) {
	metrics.KubernetesAPIInteractions.WithLabelValues(u.Path, verb).Observe(latency.Seconds())
}

func (*k8sMetrics) Increment(_ context.Context, code string, method string, host string) {
	metrics.KubernetesAPICallsTotal.WithLabelValues(host, method, code).Inc()
	// The 'code' is set to '<error>' in case an error is returned from k8s
	// more info:
	// https://github.com/kubernetes/client-go/blob/v0.18.0-rc.1/rest/request.go#L700-L703
	if code != "<error>" {
		// Consider success if status code is 2xx or 4xx
		if strings.HasPrefix(code, "2") ||
			strings.HasPrefix(code, "4") {
			k8smetrics.LastSuccessInteraction.Reset()
		}
	}
	k8smetrics.LastInteraction.Reset()
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

// WaitForCacheSyncWithTimeout calls WaitForCacheSync to block until given resources have had their caches
// synced from K8s. This will wait up to the timeout duration after starting or since the last K8s
// registered watcher event (i.e. each event causes the timeout to be pushed back). Events are recorded
// using K8sResourcesSynced.Event function. If the timeout is exceeded, an error is returned.
func (k *K8sWatcher) WaitForCacheSyncWithTimeout(timeout time.Duration, resourceNames ...string) error {
	return k.k8sResourceSynced.WaitForCacheSyncWithTimeout(timeout, resourceNames...)
}

func (k *K8sWatcher) cancelWaitGroupToSyncResources(resourceName string) {
	k.k8sResourceSynced.CancelWaitGroupToSyncResources(resourceName)
}

func (k *K8sWatcher) blockWaitGroupToSyncResources(
	stop <-chan struct{},
	swg *lock.StoppableWaitGroup,
	hasSyncedFunc cache.InformerSynced,
	resourceName string,
) {
	k.k8sResourceSynced.BlockWaitGroupToSyncResources(stop, swg, hasSyncedFunc, resourceName)
}

func (k *K8sWatcher) GetAPIGroups() []string {
	return k.k8sAPIGroups.GetGroups()
}

// WaitForCRDsToRegister will wait for the Cilium Operator to register the CRDs
// with the apiserver. This step is required before launching the full K8s
// watcher, as those resource controllers need the resources to be registered
// with K8s first.
func (k *K8sWatcher) WaitForCRDsToRegister(ctx context.Context) error {
	return synced.SyncCRDs(ctx, k.clientset, synced.AgentCRDResourceNames(), &k.k8sResourceSynced, &k.k8sAPIGroups)
}

type watcherKind int

const (
	// skip causes watcher to not be started.
	skip watcherKind = iota

	// start causes watcher to be started as soon as possible.
	start

	// afterNodeInit causes watcher to be started after local node has been initialized
	// so that e.g., local node addressing info is available.
	afterNodeInit
)

type watcherInfo struct {
	kind  watcherKind
	group string
}

var ciliumResourceToGroupMapping = map[string]watcherInfo{
	synced.CRDResourceName(v2.CNPName):            {start, k8sAPIGroupCiliumNetworkPolicyV2},
	synced.CRDResourceName(v2.CCNPName):           {start, k8sAPIGroupCiliumClusterwideNetworkPolicyV2},
	synced.CRDResourceName(v2.CEPName):            {start, k8sAPIGroupCiliumEndpointV2}, // ipcache
	synced.CRDResourceName(v2.CNName):             {start, k8sAPIGroupCiliumNodeV2},
	synced.CRDResourceName(v2.CIDName):            {skip, ""}, // Handled in pkg/k8s/identitybackend/
	synced.CRDResourceName(v2.CLRPName):           {start, k8sAPIGroupCiliumLocalRedirectPolicyV2},
	synced.CRDResourceName(v2.CEWName):            {skip, ""}, // Handled in clustermesh-apiserver/
	synced.CRDResourceName(v2.CEGPName):           {start, k8sAPIGroupCiliumEgressGatewayPolicyV2},
	synced.CRDResourceName(v2alpha1.CENPName):     {start, k8sAPIGroupCiliumEgressNATPolicyV2},
	synced.CRDResourceName(v2alpha1.CESName):      {start, k8sAPIGroupCiliumEndpointSliceV2Alpha1},
	synced.CRDResourceName(v2.CCECName):           {afterNodeInit, k8sAPIGroupCiliumClusterwideEnvoyConfigV2},
	synced.CRDResourceName(v2.CECName):            {afterNodeInit, k8sAPIGroupCiliumEnvoyConfigV2},
	synced.CRDResourceName(v2alpha1.BGPPName):     {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.LBIPPoolName): {skip, ""}, // Handled in LB IPAM
}

// resourceGroups are all of the core Kubernetes and Cilium resource groups
// which the Cilium agent watches to implement CNI functionality.
func (k *K8sWatcher) resourceGroups() (beforeNodeInitGroups, afterNodeInitGroups []string) {
	k8sGroups := []string{
		// To perform the service translation and have the BPF LB datapath
		// with the right service -> backend (k8s endpoints) translation.
		K8sAPIGroupServiceV1Core,

		// We need all network policies in place before restoring to
		// make sure we are enforcing the correct policies for each
		// endpoint before restarting.
		k8sAPIGroupNetworkingV1Core,
		// Namespaces can contain labels which are essential for
		// endpoints being restored to have the right identity.
		k8sAPIGroupNamespaceV1Core,
		// Pods can contain labels which are essential for endpoints
		// being restored to have the right identity.
		resources.K8sAPIGroupPodV1Core,
		// We need to know the node labels to populate the host
		// endpoint labels.
		k8sAPIGroupNodeV1Core,
	}

	if k.cfg.K8sIngressControllerEnabled() || k.cfg.K8sGatewayAPIEnabled() {
		// While Ingress controller is part of operator, we need to watch
		// TLS secrets in pre-defined namespace for populating Envoy xDS SDS cache.
		k8sGroups = append(k8sGroups, resources.K8sAPIGroupSecretV1Core)
	}

	// To perform the service translation and have the BPF LB datapath
	// with the right service -> backend (k8s endpoints) translation.
	if k8s.SupportsEndpointSlice() {
		k8sGroups = append(k8sGroups, resources.K8sAPIGroupEndpointSliceV1Beta1Discovery)
	} else if k8s.SupportsEndpointSliceV1() {
		k8sGroups = append(k8sGroups, resources.K8sAPIGroupEndpointSliceV1Discovery)
	}
	k8sGroups = append(k8sGroups, resources.K8sAPIGroupEndpointV1Core)
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
		case afterNodeInit:
			afterNodeInitGroups = append(afterNodeInitGroups, groupInfo.group)
		}
	}

	return append(k8sGroups, ciliumGroups...), afterNodeInitGroups
}

// InitK8sSubsystem takes a channel for which it will be closed when all
// caches essential for daemon are synchronized.
// To be called after WaitForCRDsToRegister() so that all needed CRDs have
// already been registered.
func (k *K8sWatcher) InitK8sSubsystem(ctx context.Context, cachesSynced chan struct{}) {
	log.Info("Enabling k8s event listener")
	resources, afterNodeInitResources := k.resourceGroups()
	if err := k.enableK8sWatchers(ctx, resources); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.WithError(err).Fatal("Unable to start K8s watchers for Cilium")
		}
		// If the context was canceled it means the daemon is being stopped
		return
	}
	close(k.controllersStarted)

	go func() {
		log.Info("Waiting until local node addressing before starting watchers depending on it")
		k.nodeDiscoverManager.WaitForLocalNodeInit()
		if err := k.enableK8sWatchers(ctx, afterNodeInitResources); err != nil {
			if !errors.Is(err, context.Canceled) {
				log.WithError(err).Fatal("Unable to start K8s watchers for Cilium")
			}
			// If the context was canceled it means the daemon is being stopped
			return
		}
		log.Info("Waiting until all pre-existing resources have been received")
		if err := k.WaitForCacheSyncWithTimeout(option.Config.K8sSyncTimeout, append(resources, afterNodeInitResources...)...); err != nil {
			log.WithError(err).Fatal("Timed out waiting for pre-existing resources to be received; exiting")
		}
		close(cachesSynced)
	}()
}

// WatcherConfiguration is the required configuration for enableK8sWatchers
type WatcherConfiguration interface {
	utils.ServiceConfiguration
	utils.IngressConfiguration
	utils.GatewayAPIConfiguration
}

// enableK8sWatchers starts watchers for given resources.
func (k *K8sWatcher) enableK8sWatchers(ctx context.Context, resourceNames []string) error {
	if !k.clientset.IsEnabled() {
		log.Debug("Not enabling k8s event listener because k8s is not enabled")
		return nil
	}
	asyncControllers := &sync.WaitGroup{}

	serviceOptModifier, err := utils.GetServiceListOptionsModifier(k.cfg)
	if err != nil {
		return fmt.Errorf("error creating service list option modifier: %w", err)
	}

	for _, r := range resourceNames {
		switch r {
		// Core Cilium
		case resources.K8sAPIGroupPodV1Core:
			asyncControllers.Add(1)
			go k.podsInit(k.clientset.Slim(), asyncControllers)
		case k8sAPIGroupNodeV1Core:
			k.NodesInit(k.clientset)
		case k8sAPIGroupNamespaceV1Core:
			k.namespacesInit()
		case k8sAPIGroupCiliumNodeV2:
			asyncControllers.Add(1)
			go k.ciliumNodeInit(k.clientset, asyncControllers)
		// Kubernetes built-in resources
		case k8sAPIGroupNetworkingV1Core:
			swgKNP := lock.NewStoppableWaitGroup()
			k.networkPoliciesInit(k.clientset.Slim(), swgKNP)
		case resources.K8sAPIGroupServiceV1Core:
			k.servicesInit()
		case resources.K8sAPIGroupEndpointSliceV1Beta1Discovery:
			// no-op; handled in resources.K8sAPIGroupEndpointV1Core.
		case resources.K8sAPIGroupEndpointSliceV1Discovery:
			// no-op; handled in resources.K8sAPIGroupEndpointV1Core.
		case resources.K8sAPIGroupEndpointV1Core:
			k.initEndpointsOrSlices(k.clientset.Slim(), serviceOptModifier)
		case resources.K8sAPIGroupSecretV1Core:
			swgSecret := lock.NewStoppableWaitGroup()
			// only watch secrets in specific namespaces
			k.tlsSecretInit(k.clientset.Slim(), option.Config.EnvoySecretNamespaces, swgSecret)
		// Custom resource definitions
		case k8sAPIGroupCiliumNetworkPolicyV2:
			k.ciliumNetworkPoliciesInit(k.clientset)
		case k8sAPIGroupCiliumClusterwideNetworkPolicyV2:
			k.ciliumClusterwideNetworkPoliciesInit(k.clientset)
		case k8sAPIGroupCiliumEndpointV2:
			k.initCiliumEndpointOrSlices(k.clientset, asyncControllers)
		case k8sAPIGroupCiliumEndpointSliceV2Alpha1:
			// no-op; handled in k8sAPIGroupCiliumEndpointV2
		case k8sAPIGroupCiliumLocalRedirectPolicyV2:
			//k.ciliumLocalRedirectPolicyInit(k.clientset)
		case k8sAPIGroupCiliumEgressGatewayPolicyV2:
			k.ciliumEgressGatewayPolicyInit(k.clientset)
		case k8sAPIGroupCiliumEgressNATPolicyV2:
			k.ciliumEgressNATPolicyInit(k.clientset)
		case k8sAPIGroupCiliumClusterwideEnvoyConfigV2:
			//k.ciliumClusterwideEnvoyConfigInit(k.clientset)
		case k8sAPIGroupCiliumEnvoyConfigV2:
			//k.ciliumEnvoyConfigInit(k.clientset)
		default:
			log.WithFields(logrus.Fields{
				logfields.Resource: r,
			}).Fatal("Not listening for Kubernetes resource updates for unhandled type")
		}
	}

	asyncControllers.Wait()
	return nil
}

func (k *K8sWatcher) k8sServiceHandler() {
	eventHandler := func(event *serviceCache.ServiceEvent) {
		svc := event.Service

		scopedLog := log.WithFields(logrus.Fields{
			logfields.K8sSvcName:   event.ID.Name,
			logfields.K8sNamespace: event.ID.Namespace,
		})

		scopedLog.WithFields(logrus.Fields{
			"action":      event.Action.String(),
			"service":     event.Service.String(),
			"old-service": event.OldService.String(),
			"endpoints":   event.Endpoints.String(),
		}).Debug("Kubernetes service definition changed")

		switch event.Action {
		case serviceCache.UpdateService:
			if !svc.IsExternal() {
				return
			}

			translator := k8s.NewK8sTranslator(event.ID, *event.Endpoints, false, svc.Labels, true)
			result, err := k.policyRepository.TranslateRules(translator)
			if err != nil {
				log.WithError(err).Error("Unable to repopulate egress policies from ToService rules")
				break
			} else if result.NumToServicesRules > 0 {
				// Only trigger policy updates if ToServices rules are in effect
				k.ipcache.ReleaseCIDRIdentitiesByCIDR(result.PrefixesToRelease)
				_, err := k.ipcache.AllocateCIDRs(result.PrefixesToAdd, nil, nil)
				if err != nil {
					scopedLog.WithError(err).
						Error("Unabled to allocate ipcache CIDR for toService rule")
					break
				}
				k.policyManager.TriggerPolicyUpdates(true, "Kubernetes service endpoint added")
			}

		case serviceCache.DeleteService:
			if !svc.IsExternal() {
				return
			}

			translator := k8s.NewK8sTranslator(event.ID, *event.Endpoints, true, svc.Labels, true)
			result, err := k.policyRepository.TranslateRules(translator)
			if err != nil {
				log.WithError(err).Error("Unable to depopulate egress policies from ToService rules")
				break
			} else if result.NumToServicesRules > 0 {
				// Only trigger policy updates if ToServices rules are in effect
				k.ipcache.ReleaseCIDRIdentitiesByCIDR(result.PrefixesToRelease)
				k.policyManager.TriggerPolicyUpdates(true, "Kubernetes service endpoint deleted")
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := k.K8sSvcCache.Events(ctx)
	for {
		select {
		case <-k.stop:
			cancel()
		case ev := <-events:
			eventHandler(ev)
		}
	}
}

func (k *K8sWatcher) RunK8sServiceHandler() {
	go k.k8sServiceHandler()
}

func (k *K8sWatcher) StopK8sServiceHandler() {
	close(k.stop)
}

// K8sEventProcessed is called to do metrics accounting for each processed
// Kubernetes event
func (k *K8sWatcher) K8sEventProcessed(scope, action string, status bool) {
	result := "success"
	if status == false {
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

// GetIndexer returns an index to a k8s cache store for the given resource name.
// Objects gotten using returned stores should *not* be mutated as they
// are references to internal k8s watcher store state.
func (k *K8sWatcher) GetIndexer(name string) cache.Indexer {
	switch name {
	case "ciliumendpointslice":
		k.ciliumEndpointSliceIndexerMU.RLock()
		defer k.ciliumEndpointSliceIndexerMU.RUnlock()
		return k.ciliumEndpointSliceIndexer
	case "ciliumendpoint":
		k.ciliumEndpointIndexerMU.RLock()
		defer k.ciliumEndpointIndexerMU.RUnlock()
		return k.ciliumEndpointIndexer
	default:
		panic("no such indexer: " + name)
	}
}

// SetIndexer lets you set a named cache store, only used for testing.
func (k *K8sWatcher) SetIndexer(name string, indexer cache.Indexer) {
	switch name {
	case "ciliumendpointslice":
		k.ciliumEndpointSliceIndexerMU.Lock()
		defer k.ciliumEndpointSliceIndexerMU.Unlock()
		k.ciliumEndpointSliceIndexer = indexer
	case "ciliumendpoint":
		k.ciliumEndpointIndexerMU.Lock()
		defer k.ciliumEndpointIndexerMU.Unlock()
		k.ciliumEndpointIndexer = indexer
	default:
		panic("no such indexer: " + name)
	}
}

// GetStore returns the k8s cache store for the given resource name.
// It's possible for valid resource names to return nil stores if that
// watcher is not in use.
// Objects gotten using returned stores should *not* be mutated as they
// are references to internal k8s watcher store state.
func (k *K8sWatcher) GetStore(name string) cache.Store {
	switch name {
	case "networkpolicy":
		return k.networkpolicyStore
	case "pod":
		// Wait for podStore to get initialized.
		<-k.podStoreSet
		// Access to podStore is protected by podStoreMU.
		k.podStoreMU.RLock()
		defer k.podStoreMU.RUnlock()
		return k.podStore
	case "ciliumendpoint":
		k.ciliumEndpointIndexerMU.RLock()
		defer k.ciliumEndpointIndexerMU.RUnlock()
		return k.ciliumEndpointIndexer
	case "ciliumendpointslice":
		k.ciliumEndpointSliceIndexerMU.RLock()
		defer k.ciliumEndpointSliceIndexerMU.RUnlock()
		return k.ciliumEndpointSliceIndexer
	default:
		panic("no such store: " + name)
	}
}

// initCiliumEndpointOrSlices intializes the ciliumEndpoints or ciliumEndpointSlice
func (k *K8sWatcher) initCiliumEndpointOrSlices(clientset client.Clientset, asyncControllers *sync.WaitGroup) {
	// If CiliumEndpointSlice feature is enabled, Cilium-agent watches CiliumEndpointSlice
	// objects instead of CiliumEndpoints. Hence, skip watching CiliumEndpoints if CiliumEndpointSlice
	// feature is enabled.
	asyncControllers.Add(1)
	if option.Config.EnableCiliumEndpointSlice {
		go k.ciliumEndpointSliceInit(clientset, asyncControllers)
	} else {
		go k.ciliumEndpointsInit(clientset, asyncControllers)
	}
}

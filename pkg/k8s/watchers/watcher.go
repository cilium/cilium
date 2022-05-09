// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"fmt"
	"net"
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

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/egressgateway"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discover_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discover_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/service"
)

const (
	k8sAPIGroupNodeV1Core                       = "core/v1::Node"
	k8sAPIGroupNamespaceV1Core                  = "core/v1::Namespace"
	K8sAPIGroupServiceV1Core                    = "core/v1::Service"
	K8sAPIGroupEndpointV1Core                   = "core/v1::Endpoint"
	K8sAPIGroupPodV1Core                        = "core/v1::Pods"
	K8sAPIGroupSecretV1Core                     = "core/v1::Secrets"
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
	K8sAPIGroupEndpointSliceV1Beta1Discovery    = "discovery/v1beta1::EndpointSlice"
	K8sAPIGroupEndpointSliceV1Discovery         = "discovery/v1::EndpointSlice"

	metricCNP            = "CiliumNetworkPolicy"
	metricCCNP           = "CiliumClusterwideNetworkPolicy"
	metricEndpoint       = "Endpoint"
	metricEndpointSlice  = "EndpointSlice"
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
	metricService        = "Service"
	metricCreate         = "create"
	metricDelete         = "delete"
	metricUpdate         = "update"
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

type svcManager interface {
	DeleteService(frontend loadbalancer.L3n4Addr) (bool, error)
	UpsertService(*loadbalancer.SVC) (bool, loadbalancer.ID, error)
	RegisterL7LBService(serviceName, resourceName service.Name, ports []string, proxyPort uint16) error
	RegisterL7LBServiceBackendSync(serviceName, resourceName service.Name, ports []string) error
	RemoveL7LBService(serviceName, resourceName service.Name) error
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

type K8sWatcher struct {
	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced synced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups synced.APIGroups

	// K8sSvcCache is a cache of all Kubernetes services and endpoints
	K8sSvcCache k8s.ServiceCache

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

	nodeDiscoverManager   nodeDiscoverManager
	policyManager         policyManager
	policyRepository      policyRepository
	svcManager            svcManager
	redirectPolicyManager redirectPolicyManager
	bgpSpeakerManager     bgpSpeakerManager
	egressGatewayManager  egressGatewayManager
	ipcache               *ipcache.IPCache
	envoyConfigManager    envoyConfigManager

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

	nodeStore cache.Store

	ciliumNodeStoreMU lock.RWMutex
	ciliumNodeStore   cache.Store

	namespaceStore cache.Store
	datapath       datapath.Datapath

	networkpolicyStore cache.Store

	cfg WatcherConfiguration
}

func NewK8sWatcher(
	endpointManager endpointManager,
	nodeDiscoverManager nodeDiscoverManager,
	policyManager policyManager,
	policyRepository policyRepository,
	svcManager svcManager,
	datapath datapath.Datapath,
	redirectPolicyManager redirectPolicyManager,
	bgpSpeakerManager bgpSpeakerManager,
	egressGatewayManager egressGatewayManager,
	envoyConfigManager envoyConfigManager,
	cfg WatcherConfiguration,
	ipcache *ipcache.IPCache,
) *K8sWatcher {
	return &K8sWatcher{
		K8sSvcCache:           k8s.NewServiceCache(datapath.LocalNodeAddressing()),
		endpointManager:       endpointManager,
		nodeDiscoverManager:   nodeDiscoverManager,
		policyManager:         policyManager,
		policyRepository:      policyRepository,
		svcManager:            svcManager,
		ipcache:               ipcache,
		controllersStarted:    make(chan struct{}),
		stop:                  make(chan struct{}),
		podStoreSet:           make(chan struct{}),
		datapath:              datapath,
		redirectPolicyManager: redirectPolicyManager,
		bgpSpeakerManager:     bgpSpeakerManager,
		egressGatewayManager:  egressGatewayManager,
		NodeChain:             subscriber.NewNodeChain(),
		CiliumNodeChain:       subscriber.NewCiliumNodeChain(),
		envoyConfigManager:    envoyConfigManager,
		cfg:                   cfg,
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
	return synced.SyncCRDs(ctx, synced.AgentCRDResourceNames(), &k.k8sResourceSynced, &k.k8sAPIGroups)
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
	synced.CRDResourceName(v2.CNPName):           {start, k8sAPIGroupCiliumNetworkPolicyV2},
	synced.CRDResourceName(v2.CCNPName):          {start, k8sAPIGroupCiliumClusterwideNetworkPolicyV2},
	synced.CRDResourceName(v2.CEPName):           {start, k8sAPIGroupCiliumEndpointV2}, // ipcache
	synced.CRDResourceName(v2.CNName):            {start, k8sAPIGroupCiliumNodeV2},
	synced.CRDResourceName(v2.CIDName):           {skip, ""}, // Handled in pkg/k8s/identitybackend/
	synced.CRDResourceName(v2.CLRPName):          {start, k8sAPIGroupCiliumLocalRedirectPolicyV2},
	synced.CRDResourceName(v2.CEWName):           {skip, ""}, // Handled in clustermesh-apiserver/
	synced.CRDResourceName(v2.CEGPName):          {start, k8sAPIGroupCiliumEgressGatewayPolicyV2},
	synced.CRDResourceName(v2alpha1.CENPName):    {start, k8sAPIGroupCiliumEgressNATPolicyV2},
	synced.CRDResourceName(v2alpha1.CESName):     {start, k8sAPIGroupCiliumEndpointSliceV2Alpha1},
	synced.CRDResourceName(v2.CCECName):          {afterNodeInit, k8sAPIGroupCiliumClusterwideEnvoyConfigV2},
	synced.CRDResourceName(v2.CECName):           {afterNodeInit, k8sAPIGroupCiliumEnvoyConfigV2},
	synced.CRDResourceName(v2alpha1.BGPPName):    {skip, ""}, // Handled in BGP control plane
	synced.CRDResourceName(v2alpha1.BGPPoolName): {skip, ""}, // Handled in BGP control plane
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
		K8sAPIGroupPodV1Core,
		// We need to know the node labels to populate the host
		// endpoint labels.
		k8sAPIGroupNodeV1Core,
	}

	if k.cfg.K8sIngressControllerEnabled() {
		// While Ingress controller is part of operator, we need to watch
		// TLS secrets in pre-defined namespace for populating Envoy xDS SDS cache.
		k8sGroups = append(k8sGroups, K8sAPIGroupSecretV1Core)
	}

	// To perform the service translation and have the BPF LB datapath
	// with the right service -> backend (k8s endpoints) translation.
	if k8s.SupportsEndpointSlice() {
		k8sGroups = append(k8sGroups, K8sAPIGroupEndpointSliceV1Beta1Discovery)
	} else if k8s.SupportsEndpointSliceV1() {
		k8sGroups = append(k8sGroups, K8sAPIGroupEndpointSliceV1Discovery)
	}
	k8sGroups = append(k8sGroups, K8sAPIGroupEndpointV1Core)
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
		k.WaitForCacheSync(append(resources, afterNodeInitResources...)...)
		close(cachesSynced)
	}()

	go func() {
		select {
		case <-cachesSynced:
			log.Info("All pre-existing resources have been received; continuing")
		case <-time.After(option.Config.K8sSyncTimeout):
			log.Fatal("Timed out waiting for pre-existing resources to be received; exiting")
		}
	}()
}

// WatcherConfiguration is the required configuration for enableK8sWatchers
type WatcherConfiguration interface {
	utils.ServiceConfiguration
	utils.IngressConfiguration
}

// enableK8sWatchers starts watchers for given resources.
func (k *K8sWatcher) enableK8sWatchers(ctx context.Context, resources []string) error {
	if !k8s.IsEnabled() {
		log.Debug("Not enabling k8s event listener because k8s is not enabled")
		return nil
	}
	ciliumNPClient := k8s.CiliumClient()
	asyncControllers := &sync.WaitGroup{}

	serviceOptModifier, err := utils.GetServiceListOptionsModifier(k.cfg)
	if err != nil {
		return fmt.Errorf("error creating service list option modifier: %w", err)
	}

	for _, r := range resources {
		switch r {
		// Core Cilium
		case K8sAPIGroupPodV1Core:
			asyncControllers.Add(1)
			go k.podsInit(k8s.WatcherClient(), asyncControllers)
		case k8sAPIGroupNodeV1Core:
			k.NodesInit(k8s.Client())
		case k8sAPIGroupNamespaceV1Core:
			asyncControllers.Add(1)
			go k.namespacesInit(k8s.WatcherClient(), asyncControllers)
		case k8sAPIGroupCiliumNodeV2:
			asyncControllers.Add(1)
			go k.ciliumNodeInit(ciliumNPClient, asyncControllers)
		// Kubernetes built-in resources
		case k8sAPIGroupNetworkingV1Core:
			swgKNP := lock.NewStoppableWaitGroup()
			k.networkPoliciesInit(k8s.WatcherClient(), swgKNP)
		case K8sAPIGroupServiceV1Core:
			swgSvcs := lock.NewStoppableWaitGroup()
			k.servicesInit(k8s.WatcherClient(), swgSvcs, serviceOptModifier)
		case K8sAPIGroupEndpointSliceV1Beta1Discovery:
			// no-op; handled in K8sAPIGroupEndpointV1Core.
		case K8sAPIGroupEndpointSliceV1Discovery:
			// no-op; handled in K8sAPIGroupEndpointV1Core.
		case K8sAPIGroupEndpointV1Core:
			k.initEndpointsOrSlices(k8s.WatcherClient(), serviceOptModifier)
		case K8sAPIGroupSecretV1Core:
			swgSecret := lock.NewStoppableWaitGroup()
			// only watch tls secret
			k.tlsSecretInit(k8s.WatcherClient(), option.Config.EnvoySecretNamespace, swgSecret)
		// Custom resource definitions
		case k8sAPIGroupCiliumNetworkPolicyV2:
			k.ciliumNetworkPoliciesInit(ciliumNPClient)
		case k8sAPIGroupCiliumClusterwideNetworkPolicyV2:
			k.ciliumClusterwideNetworkPoliciesInit(ciliumNPClient)
		case k8sAPIGroupCiliumEndpointV2:
			k.initCiliumEndpointOrSlices(ciliumNPClient, asyncControllers)
		case k8sAPIGroupCiliumEndpointSliceV2Alpha1:
			// no-op; handled in k8sAPIGroupCiliumEndpointV2
		case k8sAPIGroupCiliumLocalRedirectPolicyV2:
			k.ciliumLocalRedirectPolicyInit(ciliumNPClient)
		case k8sAPIGroupCiliumEgressGatewayPolicyV2:
			k.ciliumEgressGatewayPolicyInit(ciliumNPClient)
		case k8sAPIGroupCiliumEgressNATPolicyV2:
			k.ciliumEgressNATPolicyInit(ciliumNPClient)
		case k8sAPIGroupCiliumClusterwideEnvoyConfigV2:
			k.ciliumClusterwideEnvoyConfigInit(ciliumNPClient)
		case k8sAPIGroupCiliumEnvoyConfigV2:
			k.ciliumEnvoyConfigInit(ciliumNPClient)
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
	eventHandler := func(event k8s.ServiceEvent) {
		defer event.SWG.Done()

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
		case k8s.UpdateService:
			if err := k.addK8sSVCs(event.ID, event.OldService, svc, event.Endpoints); err != nil {
				scopedLog.WithError(err).Error("Unable to add/update service to implement k8s event")
			}

			if !svc.IsExternal() {
				return
			}

			translator := k8s.NewK8sTranslator(k.ipcache, event.ID, *event.Endpoints, false, svc.Labels, true)
			result, err := k.policyRepository.TranslateRules(translator)
			if err != nil {
				log.WithError(err).Error("Unable to repopulate egress policies from ToService rules")
				break
			} else if result.NumToServicesRules > 0 {
				// Only trigger policy updates if ToServices rules are in effect
				k.policyManager.TriggerPolicyUpdates(true, "Kubernetes service endpoint added")
			}

		case k8s.DeleteService:
			if err := k.delK8sSVCs(event.ID, event.Service, event.Endpoints); err != nil {
				scopedLog.WithError(err).Error("Unable to delete service to implement k8s event")
			}

			if !svc.IsExternal() {
				return
			}

			translator := k8s.NewK8sTranslator(k.ipcache, event.ID, *event.Endpoints, true, svc.Labels, true)
			result, err := k.policyRepository.TranslateRules(translator)
			if err != nil {
				log.WithError(err).Error("Unable to depopulate egress policies from ToService rules")
				break
			} else if result.NumToServicesRules > 0 {
				// Only trigger policy updates if ToServices rules are in effect
				k.policyManager.TriggerPolicyUpdates(true, "Kubernetes service endpoint deleted")
			}
		}
	}
	for {
		select {
		case <-k.stop:
			return
		case event, ok := <-k.K8sSvcCache.Events:
			if !ok {
				return
			}
			eventHandler(event)
		}
	}
}

func (k *K8sWatcher) RunK8sServiceHandler() {
	go k.k8sServiceHandler()
}

func (k *K8sWatcher) StopK8sServiceHandler() {
	close(k.stop)
}

func (k *K8sWatcher) delK8sSVCs(svc k8s.ServiceID, svcInfo *k8s.Service, se *k8s.Endpoints) error {
	// Headless services do not need any datapath implementation
	if svcInfo.IsHeadless {
		return nil
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.Name,
		logfields.K8sNamespace: svc.Namespace,
	})

	repPorts := svcInfo.UniquePorts()

	frontends := []*loadbalancer.L3n4Addr{}

	for portName, svcPort := range svcInfo.Ports {
		if !repPorts[svcPort.Port] {
			continue
		}
		repPorts[svcPort.Port] = false

		for _, feIP := range svcInfo.FrontendIPs {
			fe := loadbalancer.NewL3n4Addr(svcPort.Protocol, feIP, svcPort.Port, loadbalancer.ScopeExternal)
			frontends = append(frontends, fe)
		}

		for _, nodePortFE := range svcInfo.NodePorts[portName] {
			frontends = append(frontends, &nodePortFE.L3n4Addr)
			if svcInfo.TrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
				cpFE := nodePortFE.L3n4Addr.DeepCopy()
				cpFE.Scope = loadbalancer.ScopeInternal
				frontends = append(frontends, cpFE)
			}
		}

		for _, k8sExternalIP := range svcInfo.K8sExternalIPs {
			frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, k8sExternalIP, svcPort.Port, loadbalancer.ScopeExternal))
		}

		for _, ip := range svcInfo.LoadBalancerIPs {
			frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, ip, svcPort.Port, loadbalancer.ScopeExternal))
			if svcInfo.TrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
				frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, ip, svcPort.Port, loadbalancer.ScopeInternal))
			}
		}
	}

	for _, fe := range frontends {
		if found, err := k.svcManager.DeleteService(*fe); err != nil {
			scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(fe)).
				Warn("Error deleting service by frontend")
		} else if !found {
			scopedLog.WithField(logfields.Object, logfields.Repr(fe)).Warn("service not found")
		} else {
			scopedLog.Debugf("# cilium lb delete-service %s %d 0", fe.IP, fe.Port)
		}
	}
	return nil
}

func genCartesianProduct(
	fe net.IP,
	svcTrafficPolicy loadbalancer.SVCTrafficPolicy,
	svcType loadbalancer.SVCType,
	ports map[loadbalancer.FEPortName]*loadbalancer.L4Addr,
	bes *k8s.Endpoints,
) []loadbalancer.SVC {
	var svcSize int

	// For externalTrafficPolicy=Local we add both external and internal
	// scoped frontends, hence twice the size for only this case.
	if svcTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal &&
		(svcType == loadbalancer.SVCTypeLoadBalancer || svcType == loadbalancer.SVCTypeNodePort) {
		svcSize = len(ports) * 2
	} else {
		svcSize = len(ports)
	}

	svcs := make([]loadbalancer.SVC, 0, svcSize)
	feFamilyIPv6 := ip.IsIPv6(fe)

	for fePortName, fePort := range ports {
		var besValues []loadbalancer.Backend
		for netIP, backend := range bes.Backends {
			parsedIP := net.ParseIP(netIP)

			if backendPort := backend.Ports[string(fePortName)]; backendPort != nil && feFamilyIPv6 == ip.IsIPv6(parsedIP) {
				backendState := loadbalancer.BackendStateActive
				if backend.Terminating {
					backendState = loadbalancer.BackendStateTerminating
				}
				besValues = append(besValues, loadbalancer.Backend{
					FEPortName: string(fePortName),
					NodeName:   backend.NodeName,
					L3n4Addr: loadbalancer.L3n4Addr{
						IP:     parsedIP,
						L4Addr: *backendPort,
					},
					State: backendState,
				})
			}
		}

		// External scoped entry.
		svcs = append(svcs,
			loadbalancer.SVC{
				Frontend: loadbalancer.L3n4AddrID{
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: fe,
						L4Addr: loadbalancer.L4Addr{
							Protocol: fePort.Protocol,
							Port:     fePort.Port,
						},
						Scope: loadbalancer.ScopeExternal,
					},
					ID: loadbalancer.ID(0),
				},
				Backends: besValues,
				Type:     svcType,
			})

		// Internal scoped entry only for Local traffic policy.
		if svcSize > len(ports) {
			svcs = append(svcs,
				loadbalancer.SVC{
					Frontend: loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							IP: fe,
							L4Addr: loadbalancer.L4Addr{
								Protocol: fePort.Protocol,
								Port:     fePort.Port,
							},
							Scope: loadbalancer.ScopeInternal,
						},
						ID: loadbalancer.ID(0),
					},
					Backends: besValues,
					Type:     svcType,
				})
		}
	}
	return svcs
}

// datapathSVCs returns all services that should be set in the datapath.
func datapathSVCs(svc *k8s.Service, endpoints *k8s.Endpoints) (svcs []loadbalancer.SVC) {
	uniqPorts := svc.UniquePorts()

	clusterIPPorts := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{}
	for fePortName, fePort := range svc.Ports {
		if !uniqPorts[fePort.Port] {
			continue
		}
		uniqPorts[fePort.Port] = false
		clusterIPPorts[fePortName] = fePort
	}

	for _, frontendIP := range svc.FrontendIPs {
		dpSVC := genCartesianProduct(frontendIP, svc.TrafficPolicy, loadbalancer.SVCTypeClusterIP, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for _, ip := range svc.LoadBalancerIPs {
		dpSVC := genCartesianProduct(ip, svc.TrafficPolicy, loadbalancer.SVCTypeLoadBalancer, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for _, k8sExternalIP := range svc.K8sExternalIPs {
		dpSVC := genCartesianProduct(k8sExternalIP, svc.TrafficPolicy, loadbalancer.SVCTypeExternalIPs, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for fePortName := range clusterIPPorts {
		for _, nodePortFE := range svc.NodePorts[fePortName] {
			nodePortPorts := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				fePortName: &nodePortFE.L4Addr,
			}
			dpSVC := genCartesianProduct(nodePortFE.IP, svc.TrafficPolicy, loadbalancer.SVCTypeNodePort, nodePortPorts, endpoints)
			svcs = append(svcs, dpSVC...)
		}
	}

	lbSrcRanges := make([]*cidr.CIDR, 0, len(svc.LoadBalancerSourceRanges))
	for _, cidr := range svc.LoadBalancerSourceRanges {
		lbSrcRanges = append(lbSrcRanges, cidr)
	}

	// apply common service properties
	for i := range svcs {
		svcs[i].TrafficPolicy = svc.TrafficPolicy
		svcs[i].HealthCheckNodePort = svc.HealthCheckNodePort
		svcs[i].SessionAffinity = svc.SessionAffinity
		svcs[i].SessionAffinityTimeoutSec = svc.SessionAffinityTimeoutSec
		if svcs[i].Type == loadbalancer.SVCTypeLoadBalancer {
			svcs[i].LoadBalancerSourceRanges = lbSrcRanges
		}
	}

	return svcs
}

// hashSVCMap returns a mapping of all frontend's hash to the its corresponded
// value.
func hashSVCMap(svcs []loadbalancer.SVC) map[string]loadbalancer.L3n4Addr {
	m := map[string]loadbalancer.L3n4Addr{}
	for _, svc := range svcs {
		m[svc.Frontend.L3n4Addr.Hash()] = svc.Frontend.L3n4Addr
	}
	return m
}

func (k *K8sWatcher) addK8sSVCs(svcID k8s.ServiceID, oldSvc, svc *k8s.Service, endpoints *k8s.Endpoints) error {
	// Headless services do not need any datapath implementation
	if svc.IsHeadless {
		return nil
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svcID.Name,
		logfields.K8sNamespace: svcID.Namespace,
	})

	svcs := datapathSVCs(svc, endpoints)
	svcMap := hashSVCMap(svcs)

	if oldSvc != nil {
		// If we have oldService then we need to detect which frontends
		// are no longer in the updated service and delete them in the datapath.

		oldSVCs := datapathSVCs(oldSvc, endpoints)
		oldSVCMap := hashSVCMap(oldSVCs)

		for svcHash, oldSvc := range oldSVCMap {
			if _, ok := svcMap[svcHash]; !ok {
				if found, err := k.svcManager.DeleteService(oldSvc); err != nil {
					scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(oldSvc)).
						Warn("Error deleting service by frontend")
				} else if !found {
					scopedLog.WithField(logfields.Object, logfields.Repr(oldSvc)).Warn("service not found")
				} else {
					scopedLog.Debugf("# cilium lb delete-service %s %d 0", oldSvc.IP, oldSvc.Port)
				}
			}
		}
	}

	for _, dpSvc := range svcs {
		p := &loadbalancer.SVC{
			Frontend:                  dpSvc.Frontend,
			Backends:                  dpSvc.Backends,
			Type:                      dpSvc.Type,
			TrafficPolicy:             dpSvc.TrafficPolicy,
			SessionAffinity:           dpSvc.SessionAffinity,
			SessionAffinityTimeoutSec: dpSvc.SessionAffinityTimeoutSec,
			HealthCheckNodePort:       dpSvc.HealthCheckNodePort,
			LoadBalancerSourceRanges:  dpSvc.LoadBalancerSourceRanges,
			Name:                      svcID.Name,
			Namespace:                 svcID.Namespace,
		}
		if _, _, err := k.svcManager.UpsertService(p); err != nil {
			scopedLog.WithError(err).Error("Error while inserting service in LB map")
		}
	}
	return nil
}

// K8sEventProcessed is called to do metrics accounting for each processed
// Kubernetes event
func (k *K8sWatcher) K8sEventProcessed(scope string, action string, status bool) {
	result := "success"
	if status == false {
		result = "failed"
	}

	metrics.KubernetesEventProcessed.WithLabelValues(scope, action, result).Inc()
}

// K8sEventReceived does metric accounting for each received Kubernetes event
func (k *K8sWatcher) K8sEventReceived(scope string, action string, valid, equal bool) {
	metrics.EventTSK8s.SetToCurrentTime()
	k8smetrics.LastInteraction.Reset()

	metrics.KubernetesEventReceived.WithLabelValues(scope, action, strconv.FormatBool(valid), strconv.FormatBool(equal)).Inc()
}

// GetStore returns the k8s cache store for the given resource name.
func (k *K8sWatcher) GetStore(name string) cache.Store {
	switch name {
	case "networkpolicy":
		return k.networkpolicyStore
	case "namespace":
		return k.namespaceStore
	case "pod":
		// Wait for podStore to get initialized.
		<-k.podStoreSet
		// Access to podStore is protected by podStoreMU.
		k.podStoreMU.RLock()
		defer k.podStoreMU.RUnlock()
		return k.podStore
	default:
		return nil
	}
}

// initCiliumEndpointOrSlices intializes the ciliumEndpoints or ciliumEndpointSlice
func (k *K8sWatcher) initCiliumEndpointOrSlices(ciliumNPClient *k8s.K8sCiliumClient, asyncControllers *sync.WaitGroup) {
	// If CiliumEndpointSlice feature is enabled, Cilium-agent watches CiliumEndpointSlice
	// objects instead of CiliumEndpoints. Hence, skip watching CiliumEndpoints if CiliumEndpointSlice
	// feature is enabled.
	asyncControllers.Add(1)
	if option.Config.EnableCiliumEndpointSlice {
		go k.ciliumEndpointSliceInit(ciliumNPClient, asyncControllers)
	} else {
		go k.ciliumEndpointsInit(ciliumNPClient, asyncControllers)
	}
}

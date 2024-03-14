// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	k8s_metrics "k8s.io/client-go/tools/metrics"
	"k8s.io/client-go/util/workqueue"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ip"
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
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/service"
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

	// The client-go Register function can be called only once,
	// but there's a possibility that another package calls it and
	// registers the client-go metrics on its own registry.
	// The metrics of one who called the init first will take effect,
	// and which one wins depends on the order of package initialization.
	// Currently, controller-runtime also calls it in its init function
	// because there's an indirect dependency on controller-runtime.
	// Given the possibility that controller-runtime wins, we should set
	// the adapters directly to override the metrics registration of
	// controller-runtime as well as calling Register function.
	// Without calling Register function here, controller-runtime will have
	// a chance to override our metrics registration.
	registerOps := k8s_metrics.RegisterOpts{
		ClientCertExpiry:      nil,
		ClientCertRotationAge: nil,
		RequestLatency:        &requestLatencyAdapter{},
		RateLimiterLatency:    &rateLimiterLatencyAdapter{},
		RequestResult:         &resultAdapter{},
	}
	k8s_metrics.Register(registerOps)
	k8s_metrics.RequestLatency = registerOps.RequestLatency
	k8s_metrics.RateLimiterLatency = registerOps.RateLimiterLatency
	k8s_metrics.RequestResult = registerOps.RequestResult

	workqueue.SetProvider(workqueueMetricsProvider{})
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s-watcher")
)

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
}

type policyManager interface {
	TriggerPolicyUpdates(force bool, reason string)
}

type policyRepository interface {
	GetSelectorCache() *policy.SelectorCache
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
	policyRepository      policyRepository
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

	datapath datapath.Datapath

	cfg WatcherConfiguration

	resources agentK8s.Resources
}

func NewK8sWatcher(
	clientset client.Clientset,
	k8sResourceSynced *synced.Resources,
	k8sAPIGroups *synced.APIGroups,
	endpointManager endpointManager,
	nodeManager nodeManager,
	policyManager policyManager,
	policyRepository policyRepository,
	svcManager svcManager,
	datapath datapath.Datapath,
	redirectPolicyManager redirectPolicyManager,
	bgpSpeakerManager bgpSpeakerManager,
	cfg WatcherConfiguration,
	ipcache ipcacheManager,
	cgroupManager cgroupManager,
	resources agentK8s.Resources,
	serviceCache *k8s.ServiceCache,
	bandwidthManager datapath.BandwidthManager,
) *K8sWatcher {
	return &K8sWatcher{
		clientset:             clientset,
		k8sResourceSynced:     k8sResourceSynced,
		k8sAPIGroups:          k8sAPIGroups,
		K8sSvcCache:           serviceCache,
		endpointManager:       endpointManager,
		nodeManager:           nodeManager,
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
		cgroupManager:         cgroupManager,
		bandwidthManager:      bandwidthManager,
		cfg:                   cfg,
		resources:             resources,
	}
}

// requestLatencyAdapter implements the LatencyMetric interface from k8s client-go package
type requestLatencyAdapter struct{}

func (*requestLatencyAdapter) Observe(_ context.Context, verb string, u url.URL, latency time.Duration) {
	metrics.KubernetesAPIInteractions.WithLabelValues(u.Path, verb).Observe(latency.Seconds())
}

// rateLimiterLatencyAdapter implements the LatencyMetric interface from k8s client-go package
type rateLimiterLatencyAdapter struct{}

func (c *rateLimiterLatencyAdapter) Observe(_ context.Context, verb string, u url.URL, latency time.Duration) {
	metrics.KubernetesAPIRateLimiterLatency.WithLabelValues(u.Path, verb).Observe(latency.Seconds())
}

// resultAdapter implements the ResultMetric interface from k8s client-go package
type resultAdapter struct{}

func (r *resultAdapter) Increment(_ context.Context, code, method, host string) {
	metrics.KubernetesAPICallsTotal.WithLabelValues(host, method, code).Inc()
	// The 'code' is set to '<error>' in case an error is returned from k8s
	// more info:
	// https://github.com/kubernetes/client-go/blob/v0.18.0-rc.1/rest/request.go#L700-L703
	if code != "<error>" {
		// Consider success only if status code is 2xx
		if strings.HasPrefix(code, "2") {
			k8smetrics.LastSuccessInteraction.Reset()
		}
	}
	k8smetrics.LastInteraction.Reset()
}

type workqueueMetricsProvider struct{}

func (workqueueMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	return metrics.WorkQueueDepth.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	return metrics.WorkQueueAddsTotal.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	return metrics.WorkQueueLatency.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	return metrics.WorkQueueDuration.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return metrics.WorkQueueUnfinishedWork.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return metrics.WorkQueueLongestRunningProcessor.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	return metrics.WorkQueueRetries.WithLabelValues(name)
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
func (k *K8sWatcher) resourceGroups() (resourceGroups, waitForCachesOnly []string) {
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

	if k.cfg.K8sNetworkPolicyEnabled() {
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
// To be called after WaitForCRDsToRegister() so that all needed CRDs have
// already been registered.
func (k *K8sWatcher) InitK8sSubsystem(ctx context.Context, cachesSynced chan struct{}) {
	log.Info("Enabling k8s event listener")
	resources, waitForCachesOnly := k.resourceGroups()
	if err := k.enableK8sWatchers(ctx, resources); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.WithError(err).Fatal("Unable to start K8s watchers for Cilium")
		}
		// If the context was canceled it means the daemon is being stopped
		return
	}
	close(k.controllersStarted)

	go func() {
		log.Info("Waiting until all pre-existing resources have been received")
		allResources := append(resources, waitForCachesOnly...)
		if err := k.WaitForCacheSyncWithTimeout(option.Config.K8sSyncTimeout, allResources...); err != nil {
			log.WithError(err).Fatal("Timed out waiting for pre-existing resources to be received; exiting")
		}
		close(cachesSynced)
	}()
}

// WatcherConfiguration is the required configuration for enableK8sWatchers
type WatcherConfiguration interface {
	utils.PolicyConfiguration
}

// enableK8sWatchers starts watchers for given resources.
func (k *K8sWatcher) enableK8sWatchers(ctx context.Context, resourceNames []string) error {
	if !k.clientset.IsEnabled() {
		log.Debug("Not enabling k8s event listener because k8s is not enabled")
		return nil
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

		if logging.CanLogAt(scopedLog.Logger, logrus.DebugLevel) {
			scopedLog.WithFields(logrus.Fields{
				"action":        event.Action.String(),
				"service":       event.Service.String(),
				"old-service":   event.OldService.String(),
				"endpoints":     event.Endpoints.String(),
				"old-endpoints": event.OldEndpoints.String(),
			}).Debug("Kubernetes service definition changed")
		}

		switch event.Action {
		case k8s.UpdateService:
			if err := k.addK8sSVCs(event.ID, event.OldService, svc, event.Endpoints); err != nil {
				scopedLog.WithError(err).Error("Unable to add/update service to implement k8s event")
			}
		case k8s.DeleteService:
			if err := k.delK8sSVCs(event.ID, event.Service, event.Endpoints); err != nil {
				scopedLog.WithError(err).Error("Unable to delete service to implement k8s event")
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
			fe := loadbalancer.NewL3n4Addr(svcPort.Protocol, cmtypes.MustAddrClusterFromIP(feIP), svcPort.Port, loadbalancer.ScopeExternal)
			frontends = append(frontends, fe)
		}

		for _, nodePortFE := range svcInfo.NodePorts[portName] {
			frontends = append(frontends, &nodePortFE.L3n4Addr)
			if svcInfo.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal || svcInfo.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
				cpFE := nodePortFE.L3n4Addr.DeepCopy()
				cpFE.Scope = loadbalancer.ScopeInternal
				frontends = append(frontends, cpFE)
			}
		}

		for _, k8sExternalIP := range svcInfo.K8sExternalIPs {
			frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, cmtypes.MustAddrClusterFromIP(k8sExternalIP), svcPort.Port, loadbalancer.ScopeExternal))
		}

		for _, ip := range svcInfo.LoadBalancerIPs {
			addrCluster := cmtypes.MustAddrClusterFromIP(ip)
			frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, addrCluster, svcPort.Port, loadbalancer.ScopeExternal))
			if svcInfo.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal || svcInfo.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
				frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, addrCluster, svcPort.Port, loadbalancer.ScopeInternal))
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
			scopedLog.Debugf("# cilium lb delete-service %s %d 0", fe.AddrCluster.String(), fe.Port)
		}
	}
	return nil
}

func genCartesianProduct(
	fe net.IP,
	twoScopes bool,
	svcType loadbalancer.SVCType,
	ports map[loadbalancer.FEPortName]*loadbalancer.L4Addr,
	bes *k8s.Endpoints,
) []loadbalancer.SVC {
	var svcSize int

	// For externalTrafficPolicy=Local xor internalTrafficPolicy=Local we
	// add both external and internal scoped frontends, hence twice the size
	// for only this case.
	if twoScopes &&
		(svcType == loadbalancer.SVCTypeLoadBalancer || svcType == loadbalancer.SVCTypeNodePort) {
		svcSize = len(ports) * 2
	} else {
		svcSize = len(ports)
	}

	svcs := make([]loadbalancer.SVC, 0, svcSize)
	feFamilyIPv6 := ip.IsIPv6(fe)

	for fePortName, fePort := range ports {
		var besValues []*loadbalancer.Backend
		for addrCluster, backend := range bes.Backends {
			if backendPort := backend.Ports[string(fePortName)]; backendPort != nil && feFamilyIPv6 == addrCluster.Is6() {
				backendState := loadbalancer.BackendStateActive
				if backend.Terminating {
					backendState = loadbalancer.BackendStateTerminating
				}
				besValues = append(besValues, &loadbalancer.Backend{
					FEPortName: string(fePortName),
					NodeName:   backend.NodeName,
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: addrCluster,
						L4Addr:      *backendPort,
					},
					State:     backendState,
					Preferred: loadbalancer.Preferred(backend.Preferred),
					Weight:    loadbalancer.DefaultBackendWeight,
				})
			}
		}

		addrCluster := cmtypes.MustAddrClusterFromIP(fe)

		// External scoped entry - when external and internal policies are the same.
		svcs = append(svcs,
			loadbalancer.SVC{
				Frontend: loadbalancer.L3n4AddrID{
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: addrCluster,
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

		// Internal scoped entry - when only one of traffic policies is Local.
		if svcSize > len(ports) {
			svcs = append(svcs,
				loadbalancer.SVC{
					Frontend: loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							AddrCluster: addrCluster,
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

	twoScopes := (svc.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal) != (svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal)

	for _, frontendIP := range svc.FrontendIPs {
		dpSVC := genCartesianProduct(frontendIP, twoScopes, loadbalancer.SVCTypeClusterIP, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for _, ip := range svc.LoadBalancerIPs {
		dpSVC := genCartesianProduct(ip, twoScopes, loadbalancer.SVCTypeLoadBalancer, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for _, k8sExternalIP := range svc.K8sExternalIPs {
		dpSVC := genCartesianProduct(k8sExternalIP, twoScopes, loadbalancer.SVCTypeExternalIPs, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for fePortName := range clusterIPPorts {
		for _, nodePortFE := range svc.NodePorts[fePortName] {
			nodePortPorts := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				fePortName: &nodePortFE.L4Addr,
			}
			dpSVC := genCartesianProduct(nodePortFE.AddrCluster.Addr().AsSlice(), twoScopes, loadbalancer.SVCTypeNodePort, nodePortPorts, endpoints)
			svcs = append(svcs, dpSVC...)
		}
	}

	lbSrcRanges := make([]*cidr.CIDR, 0, len(svc.LoadBalancerSourceRanges))
	for _, cidr := range svc.LoadBalancerSourceRanges {
		lbSrcRanges = append(lbSrcRanges, cidr)
	}

	// apply common service properties
	for i := range svcs {
		svcs[i].ExtTrafficPolicy = svc.ExtTrafficPolicy
		svcs[i].IntTrafficPolicy = svc.IntTrafficPolicy
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
					scopedLog.Debugf("# cilium lb delete-service %s %d 0", oldSvc.AddrCluster.String(), oldSvc.Port)
				}
			}
		}
	}

	for _, dpSvc := range svcs {
		p := &loadbalancer.SVC{
			Frontend:                  dpSvc.Frontend,
			Backends:                  dpSvc.Backends,
			Type:                      dpSvc.Type,
			ExtTrafficPolicy:          dpSvc.ExtTrafficPolicy,
			IntTrafficPolicy:          dpSvc.IntTrafficPolicy,
			SessionAffinity:           dpSvc.SessionAffinity,
			SessionAffinityTimeoutSec: dpSvc.SessionAffinityTimeoutSec,
			HealthCheckNodePort:       dpSvc.HealthCheckNodePort,
			LoadBalancerSourceRanges:  dpSvc.LoadBalancerSourceRanges,
			Name: loadbalancer.ServiceName{
				Name:      svcID.Name,
				Namespace: svcID.Namespace,
				Cluster:   svcID.Cluster,
			},
		}
		if _, _, err := k.svcManager.UpsertService(p); err != nil {
			if errors.Is(err, service.NewErrLocalRedirectServiceExists(p.Frontend, p.Name)) {
				scopedLog.WithError(err).Debug("Error while inserting service in LB map")
			} else {
				scopedLog.WithError(err).Error("Error while inserting service in LB map")
			}
		}
	}
	return nil
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

// initCiliumEndpointOrSlices intializes the ciliumEndpoints or ciliumEndpointSlice
func (k *K8sWatcher) initCiliumEndpointOrSlices(ctx context.Context, asyncControllers *sync.WaitGroup) {
	// If CiliumEndpointSlice feature is enabled, Cilium-agent watches CiliumEndpointSlice
	// objects instead of CiliumEndpoints. Hence, skip watching CiliumEndpoints if CiliumEndpointSlice
	// feature is enabled.
	asyncControllers.Add(1)
	if option.Config.EnableCiliumEndpointSlice {
		go k.ciliumEndpointSliceInit(ctx, asyncControllers)
	} else {
		go k.ciliumEndpointsInit(ctx, asyncControllers)
	}
}

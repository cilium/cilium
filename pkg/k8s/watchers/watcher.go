// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package watchers

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/k8s/utils"
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

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	k8s_metrics "k8s.io/client-go/tools/metrics"
)

const (
	k8sAPIGroupCRD                              = "CustomResourceDefinition"
	k8sAPIGroupNodeV1Core                       = "core/v1::Node"
	k8sAPIGroupNamespaceV1Core                  = "core/v1::Namespace"
	K8sAPIGroupServiceV1Core                    = "core/v1::Service"
	K8sAPIGroupEndpointV1Core                   = "core/v1::Endpoint"
	K8sAPIGroupPodV1Core                        = "core/v1::Pods"
	k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
	k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
	k8sAPIGroupCiliumNodeV2                     = "cilium/v2::CiliumNode"
	k8sAPIGroupCiliumEndpointV2                 = "cilium/v2::CiliumEndpoint"
	K8sAPIGroupEndpointSliceV1Beta1Discovery    = "discovery/v1beta1::EndpointSlice"

	metricCNP            = "CiliumNetworkPolicy"
	metricCCNP           = "CiliumClusterwideNetworkPolicy"
	metricEndpoint       = "Endpoint"
	metricEndpointSlice  = "EndpointSlice"
	metricKNP            = "NetworkPolicy"
	metricNS             = "Namespace"
	metricCiliumNode     = "CiliumNode"
	metricCiliumEndpoint = "CiliumEndpoint"
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

	errIPCacheOwnedByNonK8s = fmt.Errorf("ipcache entry owned by kvstore or agent")
)

type endpointManager interface {
	GetEndpoints() []*endpoint.Endpoint
	GetHostEndpoint() *endpoint.Endpoint
	LookupPodName(string) *endpoint.Endpoint
	WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error
}

type nodeDiscoverManager interface {
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
	TranslateRules(translator policy.Translator) (*policy.TranslationResult, error)
}

type svcManager interface {
	DeleteService(frontend loadbalancer.L3n4Addr) (bool, error)
	UpsertService(*loadbalancer.SVC) (bool, loadbalancer.ID, error)
}

type K8sWatcher struct {
	// k8sResourceSyncedMu protects the k8sResourceSynced map.
	k8sResourceSyncedMu lock.RWMutex

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced map[string]<-chan struct{}
	// k8sResourceSyncedStopWait contains the result of
	k8sResourceSyncedStopWait map[string]bool

	// k8sAPIs is a set of k8s API in use. They are setup in EnableK8sWatcher,
	// and may be disabled while the agent runs.
	// This is on this object, instead of a global, because EnableK8sWatcher is
	// on Daemon.
	k8sAPIGroups k8sAPIGroupsUsed

	// K8sSvcCache is a cache of all Kubernetes services and endpoints
	K8sSvcCache k8s.ServiceCache

	endpointManager endpointManager

	nodeDiscoverManager nodeDiscoverManager
	policyManager       policyManager
	policyRepository    policyRepository
	svcManager          svcManager

	// controllersStarted is a channel that is closed when all controllers, i.e.,
	// k8s watchers have started listening for k8s events.
	controllersStarted chan struct{}

	podStoreMU lock.RWMutex
	podStore   cache.Store
	// podStoreSet is a channel that is closed when the podStore cache is
	// variable is written for the first time.
	podStoreSet  chan struct{}
	podStoreOnce sync.Once

	namespaceStore cache.Store
	datapath       datapath.Datapath

	networkpolicyStore cache.Store
}

func NewK8sWatcher(
	endpointManager endpointManager,
	nodeDiscoverManager nodeDiscoverManager,
	policyManager policyManager,
	policyRepository policyRepository,
	svcManager svcManager,
	datapath datapath.Datapath,
) *K8sWatcher {
	return &K8sWatcher{
		k8sResourceSynced:         map[string]<-chan struct{}{},
		k8sResourceSyncedStopWait: map[string]bool{},
		K8sSvcCache:               k8s.NewServiceCache(datapath.LocalNodeAddressing()),
		endpointManager:           endpointManager,
		nodeDiscoverManager:       nodeDiscoverManager,
		policyManager:             policyManager,
		policyRepository:          policyRepository,
		svcManager:                svcManager,
		controllersStarted:        make(chan struct{}),
		podStoreSet:               make(chan struct{}),
		datapath:                  datapath,
	}
}

// k8sAPIGroupsUsed is a lockable map to hold which k8s API Groups we have
// enabled/in-use
// Note: We can replace it with a Go 1.9 map once we require that version
type k8sAPIGroupsUsed struct {
	lock.RWMutex
	apis map[string]bool
}

func (m *k8sAPIGroupsUsed) addAPI(api string) {
	m.Lock()
	defer m.Unlock()
	if m.apis == nil {
		m.apis = make(map[string]bool)
	}
	m.apis[api] = true
}

func (m *k8sAPIGroupsUsed) removeAPI(api string) {
	m.Lock()
	defer m.Unlock()
	delete(m.apis, api)
}

func (m *k8sAPIGroupsUsed) getGroups() []string {
	m.RLock()
	defer m.RUnlock()
	groups := make([]string, 0, len(m.apis))
	for k := range m.apis {
		groups = append(groups, k)
	}
	return groups
}

// k8sMetrics implements the LatencyMetric and ResultMetric interface from
// k8s client-go package
type k8sMetrics struct{}

func (*k8sMetrics) Observe(verb string, u url.URL, latency time.Duration) {
	metrics.KubernetesAPIInteractions.WithLabelValues(u.Path, verb).Observe(latency.Seconds())
}

func (*k8sMetrics) Increment(code string, method string, host string) {
	metrics.KubernetesAPICalls.WithLabelValues(host, method, code).Inc() //TODO(sayboras): Remove deprecated metric in 1.10
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

func (k *K8sWatcher) GetAPIGroups() []string {
	return k.k8sAPIGroups.getGroups()
}

func (k *K8sWatcher) cancelWaitGroupToSyncResources(resourceName string) {
	k.k8sResourceSyncedMu.Lock()
	delete(k.k8sResourceSynced, resourceName)
	k.k8sResourceSyncedMu.Unlock()
}

// blockWaitGroupToSyncResources ensures that anything which waits on waitGroup
// waits until all objects of the specified resource stored in Kubernetes are
// received by the informer and processed by controller.
// Fatally exits if syncing these initial objects fails.
// If the given stop channel is closed, it does not fatal.
// Once the k8s caches are synced against k8s, k8sCacheSynced is also closed.
func (k *K8sWatcher) blockWaitGroupToSyncResources(
	stop <-chan struct{},
	swg *lock.StoppableWaitGroup,
	informer cache.Controller,
	resourceName string,
) {

	ch := make(chan struct{})
	k.k8sResourceSyncedMu.Lock()
	k.k8sResourceSynced[resourceName] = ch
	k.k8sResourceSyncedMu.Unlock()
	go func() {
		scopedLog := log.WithField("kubernetesResource", resourceName)
		scopedLog.Debug("waiting for cache to synchronize")
		if ok := cache.WaitForCacheSync(stop, informer.HasSynced); !ok {
			select {
			case <-stop:
				// do not fatal if the channel was stopped
				scopedLog.Debug("canceled cache synchronization")
				k.k8sResourceSyncedMu.Lock()
				// Since the wait for cache sync was canceled we need
				// to mark that k8sResourceSyncedStopWait was canceled and it
				// should not stop waiting for this resource to be synchronized.
				k.k8sResourceSyncedStopWait[resourceName] = false
				k.k8sResourceSyncedMu.Unlock()
			default:
				// Fatally exit it resource fails to sync
				scopedLog.Fatalf("failed to wait for cache to sync")
			}
		} else {
			scopedLog.Debug("cache synced")
			k.k8sResourceSyncedMu.Lock()
			// Since the wait for cache sync was not canceled we need
			// to mark that k8sResourceSyncedStopWait not canceled and it
			// should stop waiting for this resource to be synchronized.
			k.k8sResourceSyncedStopWait[resourceName] = true
			k.k8sResourceSyncedMu.Unlock()
		}
		if swg != nil {
			swg.Stop()
			swg.Wait()
		}
		close(ch)
	}()
}

// WaitForCacheSync waits for k8s caches to be synchronized for the given
// resource. Returns once all resourcesNames are synchronized with cilium-agent.
func (k *K8sWatcher) WaitForCacheSync(resourceNames ...string) {
	for _, resourceName := range resourceNames {
		k.k8sResourceSyncedMu.RLock()
		c, ok := k.k8sResourceSynced[resourceName]
		k.k8sResourceSyncedMu.RUnlock()
		if !ok {
			continue
		}
		for {
			scopedLog := log.WithField("kubernetesResource", resourceName)
			<-c
			k.k8sResourceSyncedMu.RLock()
			stopWait := k.k8sResourceSyncedStopWait[resourceName]
			k.k8sResourceSyncedMu.RUnlock()
			if stopWait {
				scopedLog.Debug("stopped waiting for caches to be synced")
				break
			}
			scopedLog.Debug("original cache sync operation was aborted, waiting for caches to be synced with a new channel...")
			time.Sleep(100 * time.Millisecond)
			k.k8sResourceSyncedMu.RLock()
			c, ok = k.k8sResourceSynced[resourceName]
			k.k8sResourceSyncedMu.RUnlock()
			if !ok {
				break
			}
		}
	}
}

// InitK8sSubsystem returns a channel for which it will be closed when all
// caches essential for daemon are synchronized.
func (k *K8sWatcher) InitK8sSubsystem() <-chan struct{} {
	if err := k.EnableK8sWatcher(option.Config.K8sWatcherQueueSize); err != nil {
		log.WithError(err).Fatal("Unable to start K8s watchers for Cilium")
	}

	cachesSynced := make(chan struct{})

	go func() {
		log.Info("Waiting until all pre-existing resources related to policy have been received")
		// Wait only for certain caches, but not all!
		// We don't wait for nodes synchronization.
		k.WaitForCacheSync(
			// To perform the service translation and have the BPF LB datapath
			// with the right service -> backend (k8s endpoints) translation.
			K8sAPIGroupServiceV1Core,
			// To perform the service translation and have the BPF LB datapath
			// with the right service -> backend (k8s endpoints) translation.
			K8sAPIGroupEndpointV1Core,
			K8sAPIGroupEndpointSliceV1Beta1Discovery,
			// We need all network policies in place before restoring to make sure
			// we are enforcing the correct policies for each endpoint before
			// restarting.
			k8sAPIGroupCiliumNetworkPolicyV2,

			k8sAPIGroupCiliumClusterwideNetworkPolicyV2,
			// We we need to know about all other nodes
			k8sAPIGroupCiliumNodeV2,
			// We need all network policies in place before restoring to make sure
			// we are enforcing the correct policies for each endpoint before
			// restarting.
			k8sAPIGroupNetworkingV1Core,
			// Namespaces can contain labels which are essential for endpoints
			// being restored to have the right identity.
			k8sAPIGroupNamespaceV1Core,
			// Pods can contain labels which are essential for endpoints
			// being restored to have the right identity.
			K8sAPIGroupPodV1Core,
		)
		// CiliumEndpoint is used to synchronize the ipcache, wait for
		// it unless it is disabled
		if !option.Config.DisableCiliumEndpointCRD {
			k.WaitForCacheSync(k8sAPIGroupCiliumEndpointV2)
		}
		close(cachesSynced)
	}()

	go func() {
		select {
		case <-cachesSynced:
			log.Info("All pre-existing resources related to policy have been received; continuing")
		case <-time.After(option.Config.K8sSyncTimeout):
			log.Fatalf("Timed out waiting for pre-existing resources related to policy to be received; exiting")
		}
	}()

	return cachesSynced
}

// EnableK8sWatcher watches for policy, services and endpoint changes on the Kubernetes
// api server defined in the receiver's daemon k8sClient.
// queueSize specifies the queue length used to serialize k8s events.
func (k *K8sWatcher) EnableK8sWatcher(queueSize uint) error {
	if !k8s.IsEnabled() {
		log.Debug("Not enabling k8s event listener because k8s is not enabled")
		return nil
	}
	log.Info("Enabling k8s event listener")

	k.k8sAPIGroups.addAPI(k8sAPIGroupCRD)

	ciliumNPClient := k8s.CiliumClient()
	asyncControllers := &sync.WaitGroup{}

	// kubernetes network policies
	swgKNP := lock.NewStoppableWaitGroup()
	k.networkPoliciesInit(k8s.WatcherCli(), swgKNP)

	serviceOptModifier, err := utils.GetServiceListOptionsModifier()
	if err != nil {
		return fmt.Errorf("error creating service list option modifier: %w", err)
	}

	// kubernetes services
	swgSvcs := lock.NewStoppableWaitGroup()
	k.servicesInit(k8s.WatcherCli(), swgSvcs, serviceOptModifier)

	// kubernetes endpoints
	swgEps := lock.NewStoppableWaitGroup()

	// We only enable either "Endpoints" or "EndpointSlice"
	switch {
	case k8s.SupportsEndpointSlice():
		// We don't add the service option modifier here, as endpointslices do not
		// mirror service proxy name label present in the corresponding service.
		connected := k.endpointSlicesInit(k8s.WatcherCli(), swgEps)
		// The cluster has endpoint slices so we should not check for v1.Endpoints
		if connected {
			break
		}
		fallthrough
	default:
		k.endpointsInit(k8s.WatcherCli(), swgEps, serviceOptModifier)
	}

	// cilium network policies
	k.ciliumNetworkPoliciesInit(ciliumNPClient)

	// cilium clusterwide network policy
	k.ciliumClusterwideNetworkPoliciesInit(ciliumNPClient)

	// cilium nodes
	asyncControllers.Add(1)
	go k.ciliumNodeInit(ciliumNPClient, asyncControllers)

	// cilium endpoints
	asyncControllers.Add(1)
	go k.ciliumEndpointsInit(ciliumNPClient, asyncControllers)

	// kubernetes pods
	asyncControllers.Add(1)
	go k.podsInit(k8s.WatcherCli(), asyncControllers)

	// kubernetes nodes
	k.nodesInit(k8s.WatcherCli())

	// kubernetes namespaces
	asyncControllers.Add(1)
	go k.namespacesInit(k8s.WatcherCli(), asyncControllers)

	asyncControllers.Wait()
	close(k.controllersStarted)

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

			translator := k8s.NewK8sTranslator(event.ID, *event.Endpoints, false, svc.Labels, true)
			result, err := k.policyRepository.TranslateRules(translator)
			if err != nil {
				log.Errorf("Unable to repopulate egress policies from ToService rules: %v", err)
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

			translator := k8s.NewK8sTranslator(event.ID, *event.Endpoints, true, svc.Labels, true)
			result, err := k.policyRepository.TranslateRules(translator)
			if err != nil {
				log.Errorf("Unable to depopulate egress policies from ToService rules: %v", err)
				break
			} else if result.NumToServicesRules > 0 {
				// Only trigger policy updates if ToServices rules are in effect
				k.policyManager.TriggerPolicyUpdates(true, "Kubernetes service endpoint deleted")
			}
		}
	}
	for {
		event, ok := <-k.K8sSvcCache.Events
		if !ok {
			return
		}
		eventHandler(event)
	}
}

func (k *K8sWatcher) RunK8sServiceHandler() {
	go k.k8sServiceHandler()
}

func (k *K8sWatcher) delK8sSVCs(svc k8s.ServiceID, svcInfo *k8s.Service, se *k8s.Endpoints) error {
	// If east-west load balancing is disabled, we should not sync(add or delete)
	// K8s service to a cilium service.
	if option.Config.DisableK8sServices {
		return nil
	}

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

		fe := loadbalancer.NewL3n4Addr(svcPort.Protocol, svcInfo.FrontendIP, svcPort.Port, loadbalancer.ScopeExternal)
		frontends = append(frontends, fe)

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

	for fePortName, fePort := range ports {
		var besValues []loadbalancer.Backend
		for ip, backend := range bes.Backends {
			if backendPort := backend.Ports[string(fePortName)]; backendPort != nil {
				besValues = append(besValues, loadbalancer.Backend{
					NodeName: backend.NodeName,
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP(ip), L4Addr: *backendPort,
					},
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
	if svc.FrontendIP != nil {
		dpSVC := genCartesianProduct(svc.FrontendIP, svc.TrafficPolicy, loadbalancer.SVCTypeClusterIP, clusterIPPorts, endpoints)
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
	// If east-west load balancing is disabled, we should not sync(add or delete)
	// K8s service to a cilium service.
	if option.Config.DisableK8sServices {
		return nil
	}

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

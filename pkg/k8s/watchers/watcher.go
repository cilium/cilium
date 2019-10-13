// Copyright 2016-2019 Authors of Cilium
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
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/serializer"

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
	k8sAPIGroupPodV1Core                        = "core/v1::Pods"
	k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
	k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
	k8sAPIGroupCiliumNodeV2                     = "cilium/v2::CiliumNode"
	k8sAPIGroupCiliumEndpointV2                 = "cilium/v2::CiliumEndpoint"
	cacheSyncTimeout                            = 3 * time.Minute

	metricCNP            = "CiliumNetworkPolicy"
	metricCCNP           = "CiliumClusterwideNetworkPolicy"
	metricEndpoint       = "Endpoint"
	metricKNP            = "NetworkPolicy"
	metricNS             = "Namespace"
	metricCiliumNode     = "CiliumNode"
	metricCiliumEndpoint = "CiliumEndpoint"
	metricPod            = "Pod"
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

	k8sMetric := &k8sMetrics{}
	k8s_metrics.Register(k8sMetric, k8sMetric)
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s-watcher")

	k8sCM = controller.NewManager()

	importMetadataCache = ruleImportMetadataCache{
		ruleImportMetadataMap: make(map[string]policyImportMetadata),
	}

	// local cache of Kubernetes Endpoints which relate to external services.
	endpointMetadataCache = endpointImportMetadataCache{
		endpointImportMetadataMap: make(map[string]endpointImportMetadata),
	}

	errIPCacheOwnedByNonK8s = fmt.Errorf("ipcache entry owned by kvstore or agent")
)

type endpointManager interface {
	GetEndpoints() []*endpoint.Endpoint
	LookupPodName(string) *endpoint.Endpoint
	WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error
}

type nodeDiscoverManager interface {
	NodeDeleted(n node.Node)
	NodeUpdated(n node.Node)
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
	UpsertService(frontend loadbalancer.L3n4AddrID, backends []loadbalancer.Backend, svcType loadbalancer.SVCType) (bool, loadbalancer.ID, error)
}

type K8sWatcher struct {
	// k8sResourceSyncedMu protects the k8sResourceSynced map.
	k8sResourceSyncedMu lock.RWMutex

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced map[string]<-chan struct{}

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
}

func NewK8sWatcher(
	endpointManager endpointManager,
	nodeDiscoverManager nodeDiscoverManager,
	policyManager policyManager,
	policyRepository policyRepository,
	svcManager svcManager,
) *K8sWatcher {
	return &K8sWatcher{
		k8sResourceSynced:   map[string]<-chan struct{}{},
		K8sSvcCache:         k8s.NewServiceCache(),
		endpointManager:     endpointManager,
		nodeDiscoverManager: nodeDiscoverManager,
		policyManager:       policyManager,
		policyRepository:    policyRepository,
		svcManager:          svcManager,
	}
}

// endpointImportMetadataCache maps the unique identifier of a Kubernetes
// Endpoint (namespace and name) to metadata about whether translation of the
// rules involving services that the endpoint corresponds to into the
// agent's policy repository at the time said rule was imported (if any error
// occurred while importing).
type endpointImportMetadataCache struct {
	mutex                     lock.RWMutex
	endpointImportMetadataMap map[string]endpointImportMetadata
}

type endpointImportMetadata struct {
	ruleTranslationError error
}

func (r *endpointImportMetadataCache) upsert(id k8s.ServiceID, ruleTranslationErr error) {
	meta := endpointImportMetadata{
		ruleTranslationError: ruleTranslationErr,
	}

	r.mutex.Lock()
	r.endpointImportMetadataMap[id.String()] = meta
	r.mutex.Unlock()
}

func (r *endpointImportMetadataCache) delete(id k8s.ServiceID) {
	r.mutex.Lock()
	delete(r.endpointImportMetadataMap, id.String())
	r.mutex.Unlock()
}

func (r *endpointImportMetadataCache) get(id k8s.ServiceID) (endpointImportMetadata, bool) {
	r.mutex.RLock()
	endpointImportMeta, ok := r.endpointImportMetadataMap[id.String()]
	r.mutex.RUnlock()
	return endpointImportMeta, ok
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
	metrics.KubernetesAPICalls.WithLabelValues(host, method, code).Inc()
	k8smetrics.LastInteraction.Reset()
}

func (k *K8sWatcher) GetAPIGroups() []string {
	return k.k8sAPIGroups.getGroups()
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
				scopedLog.Debug("canceled cache synchronization")
				// do not fatal if the channel was stopped
			default:
				// Fatally exit it resource fails to sync
				scopedLog.Fatalf("failed to wait for cache to sync")
			}
		} else {
			scopedLog.Debug("cache synced")
		}
		swg.Stop()
		swg.Wait()
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
		<-c
	}
}

// InitK8sSubsystem returns a channel for which it will be closed when all
// caches essential for daemon are synchronized.
func (k *K8sWatcher) InitK8sSubsystem() <-chan struct{} {
	if err := k.EnableK8sWatcher(option.Config.K8sWatcherQueueSize); err != nil {
		log.WithError(err).Fatal("Unable to establish connection to Kubernetes apiserver")
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
			k8sAPIGroupPodV1Core,
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
		case <-time.After(cacheSyncTimeout):
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
	serKNPs := serializer.NewFunctionQueue(queueSize)
	swgKNP := lock.NewStoppableWaitGroup()
	k.networkPoliciesInit(k8s.Client(), serKNPs, swgKNP)

	// kubernetes services
	serSvcs := serializer.NewFunctionQueue(queueSize)
	swgSvcs := lock.NewStoppableWaitGroup()
	k.servicesInit(k8s.Client(), serSvcs, swgSvcs)

	// kubernetes endpoints
	serEps := serializer.NewFunctionQueue(queueSize)
	swgEps := lock.NewStoppableWaitGroup()
	k.endpointsInit(k8s.Client(), serEps, swgEps)

	// cilium network policies
	serCNPs := serializer.NewFunctionQueue(queueSize)
	swgCNPs := lock.NewStoppableWaitGroup()
	k.ciliumNetworkPoliciesInit(ciliumNPClient, serCNPs, swgCNPs)

	// cilium clusterwide network policy
	serCCNPs := serializer.NewFunctionQueue(queueSize)
	swgCCNPs := lock.NewStoppableWaitGroup()
	k.ciliumClusterwideNetworkPoliciesInit(ciliumNPClient, serCCNPs, swgCCNPs)

	// cilium nodes
	asyncControllers.Add(1)
	serNodes := serializer.NewFunctionQueue(queueSize)
	go k.ciliumNodeInit(ciliumNPClient, serNodes, asyncControllers)

	// cilium endpoints
	asyncControllers.Add(1)
	serCiliumEndpoints := serializer.NewFunctionQueue(queueSize)
	go k.ciliumEndpointsInit(ciliumNPClient, serCiliumEndpoints, asyncControllers)

	// kubernetes pods
	asyncControllers.Add(1)
	serPods := serializer.NewFunctionQueue(queueSize)
	go k.podsInit(k8s.Client(), serPods, asyncControllers)

	// kubernetes namespaces
	serNamespaces := serializer.NewFunctionQueue(queueSize)
	go k.namespacesInit(k8s.Client(), serNamespaces)

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
			"action":    event.Action.String(),
			"service":   event.Service.String(),
			"endpoints": event.Endpoints.String(),
		}).Debug("Kubernetes service definition changed")

		switch event.Action {
		case k8s.UpdateService:
			if err := k.addK8sSVCs(event.ID, svc, event.Endpoints); err != nil {
				scopedLog.WithError(err).Error("Unable to add/update service to implement k8s event")
			}

			if !svc.IsExternal() {
				return
			}

			serviceImportMeta, cacheOK := endpointMetadataCache.get(event.ID)

			// If this is the first time adding this Endpoint, or there was an error
			// adding it last time, then try to add translate it and its
			// corresponding external service for any toServices rules which
			// select said service.
			if !cacheOK || (cacheOK && serviceImportMeta.ruleTranslationError != nil) {
				translator := k8s.NewK8sTranslator(event.ID, *event.Endpoints, false, svc.Labels, true)
				result, err := k.policyRepository.TranslateRules(translator)
				endpointMetadataCache.upsert(event.ID, err)
				if err != nil {
					log.Errorf("Unable to repopulate egress policies from ToService rules: %v", err)
					break
				} else if result.NumToServicesRules > 0 {
					// Only trigger policy updates if ToServices rules are in effect
					k.policyManager.TriggerPolicyUpdates(true, "Kubernetes service endpoint added")
				}
			} else if serviceImportMeta.ruleTranslationError == nil {
				k.policyManager.TriggerPolicyUpdates(true, "Kubernetes service endpoint updated")
			}

		case k8s.DeleteService:
			if err := k.delK8sSVCs(event.ID, event.Service, event.Endpoints); err != nil {
				scopedLog.WithError(err).Error("Unable to delete service to implement k8s event")
			}

			if !svc.IsExternal() {
				return
			}

			endpointMetadataCache.delete(event.ID)

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

		fe := loadbalancer.NewL3n4Addr(svcPort.Protocol, svcInfo.FrontendIP, svcPort.Port)
		frontends = append(frontends, fe)

		for _, nodePortFE := range svcInfo.NodePorts[portName] {
			frontends = append(frontends, &nodePortFE.L3n4Addr)
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

func (k *K8sWatcher) addK8sSVCs(svcID k8s.ServiceID, svc *k8s.Service, endpoints *k8s.Endpoints) error {
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

	uniqPorts := svc.UniquePorts()

	for fePortName, fePort := range svc.Ports {
		if !uniqPorts[fePort.Port] {
			continue
		}

		uniqPorts[fePort.Port] = false

		type frontend struct {
			addr    *loadbalancer.L3n4AddrID
			svcType loadbalancer.SVCType
		}

		frontends := []frontend{}
		frontends = append(frontends,
			frontend{
				addr: loadbalancer.NewL3n4AddrID(fePort.Protocol, svc.FrontendIP,
					fePort.Port, loadbalancer.ID(0)),
				svcType: loadbalancer.SVCTypeClusterIP,
			})

		for _, nodePortFE := range svc.NodePorts[fePortName] {
			frontends = append(frontends, frontend{
				addr:    nodePortFE,
				svcType: loadbalancer.SVCTypeNodePort,
			})
		}

		besValues := []loadbalancer.Backend{}
		for ip, portConfiguration := range endpoints.Backends {
			if backendPort := portConfiguration[string(fePortName)]; backendPort != nil {
				besValues = append(besValues, loadbalancer.Backend{
					L3n4Addr: loadbalancer.L3n4Addr{IP: net.ParseIP(ip), L4Addr: *backendPort},
				})
			}
		}

		for _, fe := range frontends {
			if _, _, err := k.svcManager.UpsertService(*fe.addr, besValues, fe.svcType); err != nil {
				scopedLog.WithError(err).Error("Error while inserting service in LB map")
			}
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

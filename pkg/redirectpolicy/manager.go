// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/k8s"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	log                 = logging.DefaultLogger.WithField(logfields.LogSubsys, "redirectpolicy")
	localRedirectSvcStr = "-local-redirect"
)

type svcManager interface {
	DeleteService(frontend lb.L3n4Addr) (bool, error)
	UpsertService(*lb.SVC) (bool, lb.ID, error)
}

type svcCache interface {
	EnsureService(svcID k8s.ServiceID, swg *lock.StoppableWaitGroup) bool
	GetServiceAddrsWithType(svcID k8s.ServiceID, svcType lb.SVCType) (map[lb.FEPortName][]*lb.L3n4Addr, int)
	GetServiceFrontendIP(svcID k8s.ServiceID, svcType lb.SVCType) net.IP
}

type StoreGetter interface {
	GetStore(name string) cache.Store
}

// podID is pod name and namespace
type podID = k8s.ServiceID

// Manager manages configurations related to Local Redirect Policies
// that enable redirecting traffic from the specified frontend to a set of node-local
// backend pods selected based on the backend configuration. To do that, it keeps
// track of add/delete events for resources like LRP, Pod and Service.
// For every local redirect policy configuration, it creates a
// new lb.SVCTypeLocalRedirect service with a frontend that has at least one node-local backend.
type Manager struct {
	// Service handler to manage service entries corresponding to redirect policies
	svcManager svcManager

	svcCache svcCache

	storeGetter StoreGetter

	warnOnce sync.Once

	// Mutex to protect against concurrent access to the maps
	mutex lock.Mutex

	// Stores mapping of all the current redirect policy frontend to their
	// respective policies
	// Frontends are namespace agnostic
	policyFrontendsByHash map[string]policyID
	// Stores mapping of redirect policy serviceID to the corresponding policyID for
	// easy lookup in policyConfigs
	policyServices map[k8s.ServiceID]policyID
	// Stores mapping of pods to redirect policies that select the pods
	policyPods map[podID][]policyID
	// Stores redirect policy configs indexed by policyID
	policyConfigs map[policyID]*LRPConfig
}

func NewRedirectPolicyManager(svc svcManager) *Manager {
	return &Manager{
		svcManager:            svc,
		policyFrontendsByHash: make(map[string]policyID),
		policyServices:        make(map[k8s.ServiceID]policyID),
		policyPods:            make(map[podID][]policyID),
		policyConfigs:         make(map[policyID]*LRPConfig),
	}
}

func (rpm *Manager) RegisterSvcCache(cache svcCache) {
	rpm.svcCache = cache
}

func (rpm *Manager) RegisterGetStores(sg StoreGetter) {
	rpm.storeGetter = sg
}

// Event handlers

// AddRedirectPolicy parses the given local redirect policy config, and updates
// internal state with the config fields.
func (rpm *Manager) AddRedirectPolicy(config LRPConfig) (bool, error) {
	rpm.warnOnce.Do(func() {
		if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnSkLookupTcp) != nil ||
			probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnSkLookupUdp) != nil {
			log.Warn("Without socket lookup kernel functionality, BPF " +
				"datapath cannot prevent potential loop caused by local-redirect" +
				"service translation. Needs kernel version >= 5.1")
		}
	})

	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()

	_, ok := rpm.policyConfigs[config.id]
	if ok {
		// TODO Existing policy update
		log.Warn("Local redirect policy updates are not handled")
		return true, nil
	}

	err := rpm.isValidConfig(config)
	if err != nil {
		return false, err
	}

	// New redirect policy
	rpm.storePolicyConfig(config)

	switch config.lrpType {
	case lrpConfigTypeAddr:
		log.WithFields(logrus.Fields{
			logfields.LRPType:                  config.lrpType,
			logfields.K8sNamespace:             config.id.Namespace,
			logfields.LRPName:                  config.id.Name,
			logfields.LRPFrontends:             config.frontendMappings,
			logfields.LRPLocalEndpointSelector: config.backendSelector,
			logfields.LRPBackendPorts:          config.backendPorts,
			logfields.LRPFrontendType:          config.frontendType,
		}).Debug("Add local redirect policy")
		pods := rpm.getLocalPodsForPolicy(&config)
		if len(pods) == 0 {
			return true, nil
		}
		rpm.processConfig(&config, pods...)

	case lrpConfigTypeSvc:
		log.WithFields(logrus.Fields{
			logfields.LRPType:                  config.lrpType,
			logfields.K8sNamespace:             config.id.Namespace,
			logfields.LRPName:                  config.id.Name,
			logfields.K8sSvcID:                 config.serviceID,
			logfields.LRPFrontends:             config.frontendMappings,
			logfields.LRPLocalEndpointSelector: config.backendSelector,
			logfields.LRPBackendPorts:          config.backendPorts,
			logfields.LRPFrontendType:          config.frontendType,
		}).Debug("Add local redirect policy")

		rpm.getAndUpsertPolicySvcConfig(&config)
	}

	return true, nil
}

// DeleteRedirectPolicy deletes the internal state associated with the given policy.
func (rpm *Manager) DeleteRedirectPolicy(config LRPConfig) error {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()

	storedConfig := rpm.policyConfigs[config.id]
	if storedConfig == nil {
		return fmt.Errorf("local redirect policy to be deleted not found")
	}
	log.WithFields(logrus.Fields{"policyID": config.id}).
		Debug("Delete local redirect policy")

	switch storedConfig.lrpType {
	case lrpConfigTypeSvc:
		rpm.deletePolicyService(storedConfig)
	case lrpConfigTypeAddr:
		for _, feM := range storedConfig.frontendMappings {
			rpm.deletePolicyFrontend(storedConfig, feM.feAddr)
		}
	}

	for p, pp := range rpm.policyPods {
		var newPolicyList []policyID
		for _, policy := range pp {
			if policy != storedConfig.id {
				newPolicyList = append(newPolicyList, policy)
			}
		}
		if len(newPolicyList) > 0 {
			rpm.policyPods[p] = newPolicyList
		} else {
			delete(rpm.policyPods, p)
		}
	}
	rpm.deletePolicyConfig(storedConfig)
	return nil
}

// OnAddService handles Kubernetes service (clusterIP type) add events, and
// updates the internal state for the policy config associated with the service.
func (rpm *Manager) OnAddService(svcID k8s.ServiceID) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()
	if len(rpm.policyConfigs) == 0 {
		return
	}

	// Check if this service is selected by any of the current policies.
	if id, ok := rpm.policyServices[svcID]; ok {
		// TODO Add unit test to assert lrpConfigType among other things.
		config := rpm.policyConfigs[id]
		if !config.checkNamespace(svcID.Namespace) {
			return
		}
		rpm.getAndUpsertPolicySvcConfig(config)
	}
}

// OnDeleteService handles Kubernetes service deletes, and deletes the internal state
// for the policy config that might be associated with the service.
func (rpm *Manager) OnDeleteService(svcID k8s.ServiceID) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()
	if len(rpm.policyConfigs) == 0 {
		return
	}

	rpm.deleteService(svcID)
}

func (rpm *Manager) OnAddPod(pod *slimcorev1.Pod) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()

	if len(rpm.policyConfigs) == 0 {
		return
	}
	// If the pod already exists in the internal cache, ignore all the subsequent
	// events since they'll be handled in the OnUpdatePod callback.
	// GH issue #13136
	// TODO add unit test
	id := k8s.ServiceID{
		Name:      pod.GetName(),
		Namespace: pod.GetNamespace(),
	}
	if _, ok := rpm.policyPods[id]; ok {
		return
	}
	rpm.OnUpdatePodLocked(pod, false, true)
}

func (rpm *Manager) OnUpdatePodLocked(pod *slimcorev1.Pod, removeOld bool, upsertNew bool) {
	if len(rpm.policyConfigs) == 0 {
		return
	}

	podIPs := k8sUtils.ValidIPs(pod.Status)
	if len(podIPs) == 0 {
		return
	}
	var podData *podMetadata
	var err error
	if podData, err = rpm.getPodMetadata(pod, podIPs); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.K8sPodName:   pod.Name,
			logfields.K8sNamespace: pod.Namespace,
		}).Error("failed to get valid pod metadata")
		return
	}

	if removeOld {
		// Check if the pod was previously selected by any of the policies.
		if policies, ok := rpm.policyPods[podData.id]; ok {
			for _, policy := range policies {
				config := rpm.policyConfigs[policy]
				rpm.deletePolicyBackends(config, podData.id)
			}
		}
	}

	if upsertNew {
		// Check if any of the current redirect policies select this pod.
		for _, config := range rpm.policyConfigs {
			if config.checkNamespace(pod.GetNamespace()) && config.policyConfigSelectsPod(podData) {
				rpm.processConfig(config, podData)
			}
		}
	}
}

func (rpm *Manager) OnUpdatePod(pod *slimcorev1.Pod, needsReassign bool, ready bool) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()
	// TODO add unit test to validate that we get callbacks only for relevant events
	rpm.OnUpdatePodLocked(pod, needsReassign || !ready, ready)
}

func (rpm *Manager) OnDeletePod(pod *slimcorev1.Pod) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()
	if len(rpm.policyConfigs) == 0 {
		return
	}
	id := k8s.ServiceID{
		Name:      pod.GetName(),
		Namespace: pod.GetNamespace(),
	}

	if policies, ok := rpm.policyPods[id]; ok {
		for _, policy := range policies {
			config := rpm.policyConfigs[policy]
			rpm.deletePolicyBackends(config, id)
		}
		delete(rpm.policyPods, id)
	}
}

// podMetadata stores relevant metadata associated with a pod that's updated during pod
// add/update events
type podMetadata struct {
	labels map[string]string
	// id the pod's name and namespace
	id podID
	// ips are pod's unique IPs
	ips []string
	// namedPorts stores pod port and protocol indexed by the port name
	namedPorts serviceStore.PortConfiguration
}

// Note: Following functions need to be called with the redirect policy manager lock.

// getAndUpsertPolicySvcConfig gets service frontends for the given config service
// and upserts the service frontends.
func (rpm *Manager) getAndUpsertPolicySvcConfig(config *LRPConfig) {
	switch config.frontendType {
	case svcFrontendAll:
		// Get all the service frontends.
		addrsByPort, feIPsCount := rpm.svcCache.GetServiceAddrsWithType(*config.serviceID,
			lb.SVCTypeClusterIP)
		config.frontendMappings = make([]*feMapping, 0, len(addrsByPort)*feIPsCount)
		for p, addrs := range addrsByPort {
			for _, addr := range addrs {
				feM := &feMapping{
					feAddr: addr,
					fePort: string(p),
				}
				config.frontendMappings = append(config.frontendMappings, feM)
			}
			rpm.updateConfigSvcFrontend(config, addrs...)
		}

	case svcFrontendSinglePort:
		// Get service frontend with the clusterIP and the policy config (unnamed) port.
		ip := rpm.svcCache.GetServiceFrontendIP(*config.serviceID, lb.SVCTypeClusterIP)
		if ip == nil {
			// The LRP will be applied when the selected service is added later.
			return
		}
		addrCluster := cmtypes.MustAddrClusterFromIP(ip)
		config.frontendMappings[0].feAddr.AddrCluster = addrCluster
		rpm.updateConfigSvcFrontend(config, config.frontendMappings[0].feAddr)

	case svcFrontendNamedPorts:
		// Get service frontends with the clusterIP and the policy config named ports.
		ports := make([]string, len(config.frontendMappings))
		for i, mapping := range config.frontendMappings {
			ports[i] = mapping.fePort
		}
		ip := rpm.svcCache.GetServiceFrontendIP(*config.serviceID, lb.SVCTypeClusterIP)
		if ip == nil {
			// The LRP will be applied when the selected service is added later.
			return
		}
		addrCluster := cmtypes.MustAddrClusterFromIP(ip)
		for _, feM := range config.frontendMappings {
			feM.feAddr.AddrCluster = addrCluster
			rpm.updateConfigSvcFrontend(config, feM.feAddr)
		}
	}

	pods := rpm.getLocalPodsForPolicy(config)
	if len(pods) > 0 {
		rpm.processConfig(config, pods...)
	}
}

// storePolicyConfig stores various state for the given policy config.
func (rpm *Manager) storePolicyConfig(config LRPConfig) {
	rpm.policyConfigs[config.id] = &config

	switch config.lrpType {
	case lrpConfigTypeAddr:
		for _, feM := range config.frontendMappings {
			rpm.policyFrontendsByHash[feM.feAddr.Hash()] = config.id
		}
	case lrpConfigTypeSvc:
		rpm.policyServices[*config.serviceID] = config.id
	}
}

// deletePolicyConfig cleans up stored state for the given policy config.
func (rpm *Manager) deletePolicyConfig(config *LRPConfig) {
	switch config.lrpType {
	case lrpConfigTypeAddr:
		for _, feM := range config.frontendMappings {
			delete(rpm.policyFrontendsByHash, feM.feAddr.Hash())
		}
	case lrpConfigTypeSvc:
		delete(rpm.policyServices, *config.serviceID)
	}
	delete(rpm.policyConfigs, config.id)
}

func (rpm *Manager) updateConfigSvcFrontend(config *LRPConfig, frontends ...*frontend) {
	for _, f := range frontends {
		rpm.policyFrontendsByHash[f.Hash()] = config.id
	}
	rpm.policyConfigs[config.id] = config
}

func (rpm *Manager) deletePolicyBackends(config *LRPConfig, podID podID) {
	for _, fe := range config.frontendMappings {
		newBes := make([]backend, 0, len(fe.podBackends))
		for _, be := range fe.podBackends {
			// Remove the pod from the frontend's backends slice, keeping the
			// order same.
			if be.podID != podID {
				newBes = append(newBes, be)
			}
		}
		fe.podBackends = newBes
		rpm.notifyPolicyBackendDelete(config, fe)
	}
}

// Deletes service entry for the specified frontend.
func (rpm *Manager) deletePolicyFrontend(config *LRPConfig, frontend *frontend) {
	found, err := rpm.svcManager.DeleteService(*frontend)
	delete(rpm.policyFrontendsByHash, frontend.Hash())
	if !found || err != nil {
		log.WithError(err).Debugf("Local redirect service for policy %v not deleted",
			config.id)
	}
}

// Updates service manager with the new set of backends now configured in 'config'.
func (rpm *Manager) notifyPolicyBackendDelete(config *LRPConfig, frontendMapping *feMapping) {
	if len(frontendMapping.podBackends) > 0 {
		rpm.upsertService(config, frontendMapping)
	} else {
		// No backends so remove the service entry.
		found, err := rpm.svcManager.DeleteService(*frontendMapping.feAddr)
		if !found || err != nil {
			log.WithError(err).Errorf("Local redirect service for policy (%v)"+
				" with frontend (%v) not deleted", config.id, frontendMapping.feAddr)
		}
		if config.lrpType == lrpConfigTypeSvc {
			if restored := rpm.svcCache.EnsureService(*config.serviceID, lock.NewStoppableWaitGroup()); restored {
				log.WithFields(logrus.Fields{
					logfields.K8sSvcID: *config.serviceID,
				}).Info("Restored service")
			}
		}
	}
}

// deletePolicyService deletes internal state associated with the specified service.
func (rpm *Manager) deletePolicyService(config *LRPConfig) {
	for _, m := range config.frontendMappings {
		rpm.deletePolicyFrontend(config, m.feAddr)
	}
	switch config.frontendType {
	case svcFrontendAll:
		config.frontendMappings = nil
	case svcFrontendSinglePort:
		fallthrough
	case svcFrontendNamedPorts:
		for _, feM := range config.frontendMappings {
			feM.feAddr.AddrCluster = cmtypes.AddrCluster{}
		}
	}
	// Retores the svc backends if there's still such a k8s svc.
	swg := lock.NewStoppableWaitGroup()
	svcID := *config.serviceID
	if restored := rpm.svcCache.EnsureService(svcID, swg); restored {
		log.WithFields(logrus.Fields{
			logfields.K8sSvcID: svcID,
		}).Debug("Restored service")
	}
}

func (rpm *Manager) deleteService(svcID k8s.ServiceID) {
	var (
		rp policyID
		ok bool
	)
	if rp, ok = rpm.policyServices[svcID]; !ok {
		return
	}
	// Get the policy config that selects this service.
	config := rpm.policyConfigs[rp]
	for _, m := range config.frontendMappings {
		rpm.deletePolicyFrontend(config, m.feAddr)
	}
	switch config.frontendType {
	case svcFrontendAll:
		config.frontendMappings = nil
	case svcFrontendSinglePort:
		fallthrough
	case svcFrontendNamedPorts:
		for _, feM := range config.frontendMappings {
			feM.feAddr.AddrCluster = cmtypes.AddrCluster{}
		}
	}
}

// upsertService upserts a service entry for the given policy config that's ready.
func (rpm *Manager) upsertService(config *LRPConfig, frontendMapping *feMapping) {
	frontendAddr := lb.L3n4AddrID{
		L3n4Addr: *frontendMapping.feAddr,
		ID:       lb.ID(0),
	}
	backendAddrs := make([]*lb.Backend, 0, len(frontendMapping.podBackends))
	for _, be := range frontendMapping.podBackends {
		backendAddrs = append(backendAddrs, &lb.Backend{
			NodeName: nodeTypes.GetName(),
			L3n4Addr: be.L3n4Addr,
		})
	}
	p := &lb.SVC{
		Name: lb.ServiceName{
			Name:      config.id.Name + localRedirectSvcStr,
			Namespace: config.id.Namespace,
		},
		Type:             lb.SVCTypeLocalRedirect,
		Frontend:         frontendAddr,
		Backends:         backendAddrs,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
	}

	if _, _, err := rpm.svcManager.UpsertService(p); err != nil {
		if errors.Is(err, service.NewErrLocalRedirectServiceExists(p.Frontend, p.Name)) {
			log.WithError(err).Debug("Error while inserting service in LB map")
		} else {
			log.WithError(err).Error("Error while inserting service in LB map")
		}
	}
}

// Returns a slice of endpoint pods metadata that are selected by the given policy config.
func (rpm *Manager) getLocalPodsForPolicy(config *LRPConfig) []*podMetadata {
	var (
		retPods []*podMetadata
		podData *podMetadata
		err     error
	)

	podStore := rpm.storeGetter.GetStore("pod")
	for _, podItem := range podStore.List() {
		pod, ok := podItem.(*slimcorev1.Pod)
		if !ok || !config.checkNamespace(pod.GetNamespace()) {
			continue
		}
		podIPs := k8sUtils.ValidIPs(pod.Status)
		if len(podIPs) == 0 {
			continue
		}
		if podData, err = rpm.getPodMetadata(pod, podIPs); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.K8sPodName:   pod.Name,
				logfields.K8sNamespace: pod.Namespace,
			}).Error("failed to get valid pod metadata")
			continue
		}
		if k8sUtils.GetLatestPodReadiness(pod.Status) != slimcorev1.ConditionTrue {
			continue
		}
		if !config.policyConfigSelectsPod(podData) {
			continue
		}
		retPods = append(retPods, podData)
	}

	return retPods
}

// isValidConfig validates the given policy config for duplicates.
// Note: The config is already sanitized.
func (rpm *Manager) isValidConfig(config LRPConfig) error {
	switch config.lrpType {
	case lrpConfigTypeAddr:
		for _, feM := range config.frontendMappings {
			fe := feM.feAddr
			id, ok := rpm.policyFrontendsByHash[fe.Hash()]
			if ok && config.id.Name != id.Name {
				return fmt.Errorf("CiliumLocalRedirectPolicy for"+
					"frontend %v already exists : %v", fe, config.id.Name)
			}
		}

	case lrpConfigTypeSvc:
		p, ok := rpm.policyServices[*config.serviceID]
		// Only 1 serviceMatcher policy is allowed for a service name within a namespace.
		if ok && config.id.Namespace != "" &&
			config.id.Namespace == rpm.policyConfigs[p].id.Namespace {
			return fmt.Errorf("CiliumLocalRedirectPolicy for"+
				" service %v already exists in namespace %v", config.serviceID,
				config.id.Namespace)
		}
	}

	return nil
}

func (rpm *Manager) processConfig(config *LRPConfig, pods ...*podMetadata) {
	if config.lrpType == lrpConfigTypeSvc && len(config.frontendMappings) == 0 {
		// Frontend information will be available when the selected service is added.
		return
	}
	switch config.frontendType {
	case svcFrontendSinglePort:
		fallthrough
	case addrFrontendSinglePort:
		rpm.processConfigWithSinglePort(config, pods...)
	case svcFrontendNamedPorts:
		fallthrough
	case addrFrontendNamedPorts:
		rpm.processConfigWithNamedPorts(config, pods...)
	case svcFrontendAll:
		if len(config.frontendMappings) > 1 {
			// The retrieved service frontend has multiple ports, in which case
			// Kubernetes mandates that the ports be named.
			rpm.processConfigWithNamedPorts(config, pods...)
		} else {
			// The retrieved service frontend has only 1 port, in which case
			// port names are optional.
			rpm.processConfigWithSinglePort(config, pods...)
		}
	}
}

// processConfigWithSinglePort upserts a policy config frontend with the corresponding
// backends.
// Frontend <ip, port, protocol> is mapped to backend <ip, port, protocol> entry.
// If a pod has multiple IPs, then there will be multiple backend entries created
// for the pod with common <port, protocol>.
func (rpm *Manager) processConfigWithSinglePort(config *LRPConfig, pods ...*podMetadata) {
	var bes4 []backend
	var bes6 []backend

	// Generate and map pod backends to the policy frontend. The policy config
	// is already sanitized, and has matching backend and frontend port protocol.
	// We currently don't check which backends are updated before upserting a
	// a service with the corresponding frontend. This can be optimized when LRPs
	// are scaled up.
	bePort := config.backendPorts[0]
	feM := config.frontendMappings[0]
	for _, pod := range pods {
		for _, ip := range pod.ips {
			beIP := net.ParseIP(ip)
			if beIP == nil {
				continue
			}
			be := backend{
				lb.L3n4Addr{
					AddrCluster: cmtypes.MustParseAddrCluster(ip),
					L4Addr: lb.L4Addr{
						Protocol: bePort.l4Addr.Protocol,
						Port:     bePort.l4Addr.Port,
					},
				}, pod.id,
			}
			if feM.feAddr.AddrCluster.Is4() && be.AddrCluster.Is4() {
				if option.Config.EnableIPv4 {
					bes4 = append(bes4, be)
				}
			} else if feM.feAddr.AddrCluster.Is6() && be.AddrCluster.Is6() {
				if option.Config.EnableIPv6 {
					bes6 = append(bes6, be)
				}
			}
		}
		if len(bes4) > 0 {
			rpm.updateFrontendMapping(config, feM, pod.id, bes4)
		} else if len(bes6) > 0 {
			rpm.updateFrontendMapping(config, feM, pod.id, bes6)
		}
	}
	rpm.upsertService(config, feM)
}

// processConfigWithNamedPorts upserts policy config frontends to the corresponding
// backends matched by port names.
func (rpm *Manager) processConfigWithNamedPorts(config *LRPConfig, pods ...*podMetadata) {
	// Generate backends for the policy config's backend named ports, and then
	// map the backends to policy frontends based on the named ports.
	// We currently don't check which backends are updated before upserting a
	// a service with the corresponding frontend. This can be optimized if LRPs
	// are scaled up.
	upsertFes := make([]*feMapping, 0, len(config.frontendMappings))
	for _, feM := range config.frontendMappings {
		namedPort := feM.fePort
		var (
			bes4   []backend
			bes6   []backend
			bePort *bePortInfo
			ok     bool
		)
		if bePort, ok = config.backendPortsByPortName[namedPort]; !ok {
			// The frontend named port not found in the backend ports map.
			continue
		}
		if bePort.l4Addr.Protocol != feM.feAddr.Protocol {
			continue
		}
		for _, pod := range pods {
			if _, ok = pod.namedPorts[namedPort]; ok {
				// Generate pod backends.
				for _, ip := range pod.ips {
					beIP := net.ParseIP(ip)
					if beIP == nil {
						continue
					}
					be := backend{
						lb.L3n4Addr{
							AddrCluster: cmtypes.MustParseAddrCluster(ip),
							L4Addr: lb.L4Addr{
								Protocol: bePort.l4Addr.Protocol,
								Port:     bePort.l4Addr.Port,
							},
						},
						pod.id,
					}
					if feM.feAddr.AddrCluster.Is4() && be.AddrCluster.Is4() {
						if option.Config.EnableIPv4 {
							bes4 = append(bes4, be)
						}
					} else if feM.feAddr.AddrCluster.Is6() && be.AddrCluster.Is6() {
						if option.Config.EnableIPv6 {
							bes6 = append(bes6, be)
						}
					}
				}
			}
			if len(bes4) > 0 {
				rpm.updateFrontendMapping(config, feM, pod.id, bes4)
			} else if len(bes6) > 0 {
				rpm.updateFrontendMapping(config, feM, pod.id, bes6)
			}
		}
		if len(bes4) > 0 || len(bes6) > 0 {
			upsertFes = append(upsertFes, feM)
		}
	}
	for i := range upsertFes {
		rpm.upsertService(config, upsertFes[i])
	}
}

// updateFrontendMapping updates policy config internal state and updates
// the policy frontend mapped backends.
func (rpm *Manager) updateFrontendMapping(config *LRPConfig, frontendMapping *feMapping, podID podID, backends []backend) {
	newFePods := make([]backend, 0, len(frontendMapping.podBackends)+len(backends))
	updatePodBes := true
	// Update the frontend mapped backends slice, keeping the order same.
	for _, be := range frontendMapping.podBackends {
		if be.podID == podID {
			if updatePodBes {
				updatePodBes = false
				// Get the updated backends for the given pod.
				newFePods = append(newFePods, backends...)
			}
		} else {
			// Collect the unchanged backends for other pods.
			newFePods = append(newFePods, be)
		}
	}
	if updatePodBes {
		// New backend pod for the frontend
		newFePods = append(newFePods, backends...)
	}
	frontendMapping.podBackends = newFePods

	if podPolicies, ok := rpm.policyPods[podID]; ok {
		newPodPolicy := true
		for _, poID := range podPolicies {
			// Existing pod policy update
			if poID == config.id {
				newPodPolicy = false
				break
			}
		}
		if newPodPolicy {
			// Pod selected by a new policy
			rpm.policyPods[podID] = append(rpm.policyPods[podID], config.id)
		}
	} else {
		// Pod selected by a policy for the first time
		pp := []policyID{config.id}
		rpm.policyPods[podID] = pp
	}
}

// TODO This function along with podMetadata can potentially be removed. We
// can directly reference the relevant pod metedata on-site.
func (rpm *Manager) getPodMetadata(pod *slimcorev1.Pod, podIPs []string) (*podMetadata, error) {
	namedPorts := make(serviceStore.PortConfiguration)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == "" {
				continue
			}
			if _, err := u8proto.ParseProtocol(string(port.Protocol)); err != nil {
				return nil, err
			}
			if port.ContainerPort < 1 || port.ContainerPort > 65535 {
				return nil, fmt.Errorf("invalid container port %v",
					port.ContainerPort)
			}
			namedPorts[port.Name] = lb.NewL4Addr(lb.L4Type(port.Protocol),
				uint16(port.ContainerPort))
		}
	}
	return &podMetadata{
		ips:        podIPs,
		labels:     pod.GetLabels(),
		namedPorts: namedPorts,
		id: k8s.ServiceID{
			Name:      pod.GetName(),
			Namespace: pod.GetNamespace(),
		},
	}, nil
}

func (rpm *Manager) GetLRPs() []*LRPConfig {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()

	lrps := make([]*LRPConfig, 0, len(rpm.policyConfigs))
	for _, lrp := range rpm.policyConfigs {
		lrps = append(lrps, lrp)
	}

	return lrps
}

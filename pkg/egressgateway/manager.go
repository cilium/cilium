// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway")
)

type k8sCacheSyncedChecker interface {
	K8sCacheIsSynced() bool
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	lock.Mutex

	// k8sCacheSyncedChecker is used to check if the agent has synced its
	// cache with the k8s API server
	k8sCacheSyncedChecker k8sCacheSyncedChecker

	// nodeDataStore stores node name to node mapping
	nodeDataStore map[string]nodeTypes.Node

	// nodes stores nodes sorted by their name
	nodes []nodeTypes.Node

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator
}

// NewEgressGatewayManager returns a new Egress Gateway Manager.
func NewEgressGatewayManager(k8sCacheSyncedChecker k8sCacheSyncedChecker, identityAlocator identityCache.IdentityAllocator) *Manager {
	manager := &Manager{
		k8sCacheSyncedChecker: k8sCacheSyncedChecker,
		nodeDataStore:         make(map[string]nodeTypes.Node),
		policyConfigs:         make(map[policyID]*PolicyConfig),
		epDataStore:           make(map[endpointID]*endpointMetadata),
		identityAllocator:     identityAlocator,
	}

	manager.runReconciliationAfterK8sSync()

	return manager
}

// getIdentityLabels waits for the global identities to be populated to the cache,
// then looks up identity by ID from the cached identity allocator and return its labels.
func (manager *Manager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	identityCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()
	if err := manager.identityAllocator.WaitForInitialGlobalIdentities(identityCtx); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %v", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(identityCtx, identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// runReconciliationAfterK8sSync spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) runReconciliationAfterK8sSync() {
	go func() {
		for {
			if manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
				break
			}

			time.Sleep(1 * time.Second)
		}

		manager.Lock()
		manager.reconcile()
		manager.Unlock()
	}()
}

// Event handlers

// OnAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) OnAddEgressPolicy(config PolicyConfig) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumEgressNATPolicyName, config.id.Name)

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Info("Added CiliumEgressNATPolicy")
	} else {
		logger.Info("Updated CiliumEgressNATPolicy")
	}

	manager.policyConfigs[config.id] = &config

	manager.reconcile()
}

// OnDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (manager *Manager) OnDeleteEgressPolicy(configID policyID) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumEgressNATPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete CiliumEgressNATPolicy: policy not found")
		return
	}

	logger.Info("Deleted CiliumEgressNATPolicy")

	delete(manager.policyConfigs, configID)

	manager.reconcile()
}

// OnUpdateEndpoint is the event handler for endpoint additions and updates.
func (manager *Manager) OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
	})

	if len(endpoint.Networking.Addressing) == 0 {
		logger.WithError(err).
			Error("Failed to get valid endpoint IPs, skipping update to egress policy.")
		return
	}

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.WithError(err).
			Error("Failed to get idenity labels for endpoint, skipping update to egress policy.")
		return
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return
	}

	manager.epDataStore[epData.id] = epData

	manager.reconcile()
}

// OnDeleteEndpoint is the event handler for endpoint deletions.
func (manager *Manager) OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.Lock()
	defer manager.Unlock()

	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	delete(manager.epDataStore, id)

	manager.reconcile()
}

// OnUpdateNode is the event handler for node additions and updates.
func (manager *Manager) OnUpdateNode(node nodeTypes.Node) {
	manager.Lock()
	defer manager.Unlock()
	manager.nodeDataStore[node.Name] = node
	manager.onChangeNodeLocked()
}

// OnDeleteNode is the event handler for node deletions.
func (manager *Manager) OnDeleteNode(node nodeTypes.Node) {
	manager.Lock()
	defer manager.Unlock()
	delete(manager.nodeDataStore, node.Name)
	manager.onChangeNodeLocked()
}

func (manager *Manager) onChangeNodeLocked() {
	manager.nodes = []nodeTypes.Node{}
	for _, n := range manager.nodeDataStore {
		manager.nodes = append(manager.nodes, n)
	}
	sort.Slice(manager.nodes, func(i, j int) bool {
		return manager.nodes[i].Name < manager.nodes[j].Name
	})
	manager.reconcile()
}

func (manager *Manager) regenerateGatewayConfigs() {
	for _, policyConfig := range manager.policyConfigs {
		policyConfig.regenerateGatewayConfig(manager)
	}
}

func (manager *Manager) addMissingIpRulesAndRoutes() (shouldRetry bool) {
	addIPRulesAndRoutesForConfig := func(endpointIP net.IP, dstCIDR *net.IPNet, gwc *gatewayConfig) {
		if !gwc.localNodeConfiguredAsGateway {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        endpointIP,
			logfields.DestinationCIDR: dstCIDR.String(),
			logfields.EgressIP:        gwc.egressIP.IP,
			logfields.LinkIndex:       gwc.ifaceIndex,
		})

		if err := addEgressIpRule(endpointIP, dstCIDR, gwc.egressIP.IP, gwc.ifaceIndex); err != nil {
			logger.WithError(err).Warn("Can't add IP rule")
			shouldRetry = true
		} else {
			logger.Info("Added IP rule")
		}

		if err := addEgressIpRoutes(gwc.egressIP, gwc.ifaceIndex); err != nil {
			logger.WithError(err).Warn("Can't add IP routes")
			return
		}
		logger.Info("Added IP routes")
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndDestination(manager.epDataStore, addIPRulesAndRoutesForConfig)
	}

	return
}

func (manager *Manager) removeUnusedIpRulesAndRoutes() {
	logger := log.WithFields(logrus.Fields{})

	ipRules, err := listEgressIpRules()
	if err != nil {
		logger.WithError(err).Warn("Cannot list IP rules")
		return
	}

	// Delete all IP rules that don't have a matching egress gateway rule
nextIpRule:
	for _, ipRule := range ipRules {
		matchFunc := func(endpointIP net.IP, dstCIDR *net.IPNet, gwc *gatewayConfig) bool {
			return gwc.localNodeConfiguredAsGateway &&
				ipRule.Src.IP.Equal(endpointIP) && ipRule.Dst.String() == dstCIDR.String()
		}

		for _, policyConfig := range manager.policyConfigs {
			if policyConfig.matches(manager.epDataStore, matchFunc) {
				continue nextIpRule
			}
		}

		deleteIpRule(ipRule)
	}

	// Build a list of all the network interfaces that are being actively used by egress gateway
	activeEgressGwIfaceIndexes := map[int]struct{}{}
	for _, policyConfig := range manager.policyConfigs {
		for _, endpoint := range manager.epDataStore {
			if policyConfig.selectsEndpoint(endpoint) {
				if policyConfig.gatewayConfig.localNodeConfiguredAsGateway {
					activeEgressGwIfaceIndexes[policyConfig.gatewayConfig.ifaceIndex] = struct{}{}
				}
			}
		}
	}

	// Then go through each interface on the node
	links, err := netlink.LinkList()
	if err != nil {
		logger.WithError(err).Error("Cannot list interfaces")
		return
	}

	for _, l := range links {
		// If egress gateway is active for this interface, move to the next interface
		if _, ok := activeEgressGwIfaceIndexes[l.Attrs().Index]; ok {
			continue
		}

		// Otherwise delete the whole routing table for that interface
		deleteIpRouteTable(egressGatewayRoutingTableIdx(l.Attrs().Index))
	}
}

func (manager *Manager) addMissingEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	egressmap.EgressPolicyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	addEgressRule := func(endpointIP net.IP, dstCIDR *net.IPNet, gwc *gatewayConfig) {
		policyKey := egressmap.NewEgressPolicyKey4(endpointIP, dstCIDR.IP, dstCIDR.Mask)
		policyVal, policyPresent := egressPolicies[policyKey]

		if policyPresent && policyVal.Match(gwc.egressIP.IP, gwc.gatewayIP) {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        endpointIP,
			logfields.DestinationCIDR: dstCIDR.String(),
			logfields.EgressIP:        gwc.egressIP.IP,
			logfields.GatewayIP:       gwc.gatewayIP,
		})

		if err := egressmap.EgressPolicyMap.Update(endpointIP, *dstCIDR, gwc.egressIP.IP, gwc.gatewayIP); err != nil {
			logger.WithError(err).Error("Error applying egress gateway policy")
		} else {
			logger.Info("Egress gateway policy applied")
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndDestination(manager.epDataStore, addEgressRule)
	}
}

// removeUnusedEgressRules is responsible for removing any entry in the egress policy BPF map which
// is not baked by an actual k8s CiliumEgressNATPolicy.
func (manager *Manager) removeUnusedEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	egressmap.EgressPolicyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

nextPolicyKey:
	for policyKey, policyVal := range egressPolicies {
		matchPolicy := func(endpointIP net.IP, dstCIDR *net.IPNet, gwc *gatewayConfig) bool {
			return policyKey.Match(endpointIP, dstCIDR) && policyVal.Match(gwc.egressIP.IP, gwc.gatewayIP)
		}

		for _, policyConfig := range manager.policyConfigs {
			if policyConfig.matches(manager.epDataStore, matchPolicy) {
				continue nextPolicyKey
			}
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        policyKey.GetSourceIP(),
			logfields.DestinationCIDR: policyKey.GetDestCIDR().String(),
			logfields.EgressIP:        policyVal.GetEgressIP(),
			logfields.GatewayIP:       policyVal.GetGatewayIP(),
		})

		if err := egressmap.EgressPolicyMap.Delete(policyKey.GetSourceIP(), *policyKey.GetDestCIDR()); err != nil {
			logger.WithError(err).Error("Error removing egress gateway policy")
		} else {
			logger.Info("Egress gateway policy removed")
		}
	}
}

// reconcile is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (egress policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcile() {
	if !manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
		return
	}

	manager.regenerateGatewayConfigs()

	if option.Config.InstallEgressGatewayRoutes {
		shouldRetry := manager.addMissingIpRulesAndRoutes()
		manager.removeUnusedIpRulesAndRoutes()

		if shouldRetry {
			manager.addMissingIpRulesAndRoutes()
		}
	}

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingEgressRules()
	manager.removeUnusedEgressRules()
}

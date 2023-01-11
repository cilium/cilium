// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"fmt"
	"net"
	"sort"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type Manager interface {
	OnAddEgressPolicy(config PolicyConfig)
	OnDeleteEgressPolicy(configID types.NamespacedName)
	OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint)
	OnDeleteNode(node nodeTypes.Node)
	OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint)
	OnUpdateNode(node nodeTypes.Node)
}

var Cell = cell.Module(
	"egress-gateway",
	"Egress Gateway",

	cell.Provide(NewEgressGatewayManager),
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway")
)

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type manager struct {
	lock.Mutex

	// k8sCacheSyncedChecker is used to check if the agent has synced its
	// cache with the k8s API server
	k8sCacheSyncedChecker *k8s.CacheSyncedChecker

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
func NewEgressGatewayManager(
	lifecycle hive.Lifecycle,
	config *option.DaemonConfig,
	k8sCacheSyncedChecker *k8s.CacheSyncedChecker,
	identityAllocatorPromise promise.Promise[identityCache.IdentityAllocator],
) Manager {
	if !config.EnableIPv4EgressGateway {
		return nil
	}

	manager := &manager{
		k8sCacheSyncedChecker: k8sCacheSyncedChecker,
		nodeDataStore:         make(map[string]nodeTypes.Node),
		policyConfigs:         make(map[policyID]*PolicyConfig),
		epDataStore:           make(map[endpointID]*endpointMetadata),
	}

	lifecycle.Append(hive.Hook{OnStart: func(hc hive.HookContext) (err error) {
		manager.identityAllocator, err = identityAllocatorPromise.Await(hc)
		if err != nil {
			return err
		}

		manager.runReconciliationAfterK8sSync()

		return nil
	}})

	return manager
}

// getIdentityLabels waits for the global identities to be populated to the cache,
// then looks up identity by ID from the cached identity allocator and return its labels.
func (mgr *manager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	identityCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()
	if err := mgr.identityAllocator.WaitForInitialGlobalIdentities(identityCtx); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %v", err)
	}

	identity := mgr.identityAllocator.LookupIdentityByID(identityCtx, identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// runReconciliationAfterK8sSync spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (mgr *manager) runReconciliationAfterK8sSync() {
	go func() {
		mgr.k8sCacheSyncedChecker.Wait()

		mgr.Lock()
		mgr.reconcile()
		mgr.Unlock()
	}()
}

// Event handlers

// OnAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (mgr *manager) OnAddEgressPolicy(config PolicyConfig) {
	mgr.Lock()
	defer mgr.Unlock()

	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, config.id.Name)

	if _, ok := mgr.policyConfigs[config.id]; !ok {
		logger.Debug("Added CiliumEgressGatewayPolicy")
	} else {
		logger.Debug("Updated CiliumEgressGatewayPolicy")
	}

	mgr.policyConfigs[config.id] = &config

	mgr.reconcile()
}

// OnDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (mgr *manager) OnDeleteEgressPolicy(configID policyID) {
	mgr.Lock()
	defer mgr.Unlock()

	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, configID.Name)

	if mgr.policyConfigs[configID] == nil {
		logger.Warn("Can't delete CiliumEgressGatewayPolicy: policy not found")
		return
	}

	logger.Debug("Deleted CiliumEgressGatewayPolicy")

	delete(mgr.policyConfigs, configID)

	mgr.reconcile()
}

// OnUpdateEndpoint is the event handler for endpoint additions and updates.
func (mgr *manager) OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

	mgr.Lock()
	defer mgr.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
	})

	if len(endpoint.Networking.Addressing) == 0 {
		logger.WithError(err).
			Error("Failed to get valid endpoint IPs, skipping update to egress policy.")
		return
	}

	if identityLabels, err = mgr.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.WithError(err).
			Error("Failed to get identity labels for endpoint, skipping update to egress policy.")
		return
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return
	}

	mgr.epDataStore[epData.id] = epData

	mgr.reconcile()
}

// OnDeleteEndpoint is the event handler for endpoint deletions.
func (mgr *manager) OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	mgr.Lock()
	defer mgr.Unlock()

	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	delete(mgr.epDataStore, id)

	mgr.reconcile()
}

// OnUpdateNode is the event handler for node additions and updates.
func (mgr *manager) OnUpdateNode(node nodeTypes.Node) {
	mgr.Lock()
	defer mgr.Unlock()
	mgr.nodeDataStore[node.Name] = node
	mgr.onChangeNodeLocked()
}

// OnDeleteNode is the event handler for node deletions.
func (mgr *manager) OnDeleteNode(node nodeTypes.Node) {
	mgr.Lock()
	defer mgr.Unlock()
	delete(mgr.nodeDataStore, node.Name)
	mgr.onChangeNodeLocked()
}

func (mgr *manager) onChangeNodeLocked() {
	mgr.nodes = []nodeTypes.Node{}
	for _, n := range mgr.nodeDataStore {
		mgr.nodes = append(mgr.nodes, n)
	}
	sort.Slice(mgr.nodes, func(i, j int) bool {
		return mgr.nodes[i].Name < mgr.nodes[j].Name
	})
	mgr.reconcile()
}

func (mgr *manager) regenerateGatewayConfigs() {
	for _, policyConfig := range mgr.policyConfigs {
		policyConfig.regenerateGatewayConfig(mgr)
	}
}

func (mgr *manager) addMissingIpRulesAndRoutes(isRetry bool) (shouldRetry bool) {
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
			if isRetry {
				logger.WithError(err).Warn("Can't add IP rule")
			} else {
				logger.WithError(err).Debug("Can't add IP rule, will retry")
				shouldRetry = true
			}
		} else {
			logger.Debug("Added IP rule")
		}

		if err := addEgressIpRoutes(gwc.egressIP, gwc.ifaceIndex); err != nil {
			logger.WithError(err).Warn("Can't add IP routes")
			return
		}
		logger.Debug("Added IP routes")
	}

	for _, policyConfig := range mgr.policyConfigs {
		policyConfig.forEachEndpointAndDestination(mgr.epDataStore, addIPRulesAndRoutesForConfig)
	}

	return
}

func (mgr *manager) removeUnusedIpRulesAndRoutes() {
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

		for _, policyConfig := range mgr.policyConfigs {
			if policyConfig.matches(mgr.epDataStore, matchFunc) {
				continue nextIpRule
			}
		}

		deleteIpRule(ipRule)
	}

	// Build a list of all the network interfaces that are being actively used by egress gateway
	activeEgressGwIfaceIndexes := map[int]struct{}{}
	for _, policyConfig := range mgr.policyConfigs {
		for _, endpoint := range mgr.epDataStore {
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

func (mgr *manager) addMissingEgressRules() {
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
			logger.Debug("Egress gateway policy applied")
		}
	}

	for _, policyConfig := range mgr.policyConfigs {
		policyConfig.forEachEndpointAndDestination(mgr.epDataStore, addEgressRule)
	}
}

// removeUnusedEgressRules is responsible for removing any entry in the egress policy BPF map which
// is not baked by an actual k8s CiliumEgressGatewayPolicy.
func (mgr *manager) removeUnusedEgressRules() {
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

		for _, policyConfig := range mgr.policyConfigs {
			if policyConfig.matches(mgr.epDataStore, matchPolicy) {
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
			logger.Debug("Egress gateway policy removed")
		}
	}
}

// reconcile is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (egress policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (mgr *manager) reconcile() {
	if !mgr.k8sCacheSyncedChecker.IsSynced() {
		return
	}

	mgr.regenerateGatewayConfigs()

	if option.Config.InstallEgressGatewayRoutes {
		shouldRetry := mgr.addMissingIpRulesAndRoutes(false)
		mgr.removeUnusedIpRulesAndRoutes()

		if shouldRetry {
			mgr.addMissingIpRulesAndRoutes(true)
		}
	}

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	mgr.addMissingEgressRules()
	mgr.removeUnusedEgressRules()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"fmt"
	"net"
	"sort"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
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
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway")
	// GatewayNotFoundIPv4 is a special IP value used as gatewayIP in the BPF policy
	// map to indicate no gateway was found for the given policy
	GatewayNotFoundIPv4 = net.ParseIP("0.0.0.0")
	// ExcludedCIDRIPv4 is a special IP value used as gatewayIP in the BPF policy map
	// to indicate the entry is for an excluded CIDR and should skip egress gateway
	ExcludedCIDRIPv4 = net.ParseIP("0.0.0.1")
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"egressgateway",
	"Egress Gateway allows originating traffic from specific IPv4 addresses",
	cell.Config(defaultConfig),
	cell.Provide(NewEgressGatewayManager),
)

type eventType int

const (
	eventNone = iota
	eventK8sSyncDone
	eventAddPolicy
	eventDeletePolicy
	eventUpdateNode
	eventDeleteNode
	eventUpdateEndpoint
	eventDeleteEndpoint
)

type Config struct {
	// Install egress gateway IP rules and routes in order to properly steer
	// egress gateway traffic to the correct ENI interface
	InstallEgressGatewayRoutes bool
}

var defaultConfig = Config{
	InstallEgressGatewayRoutes: false,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("install-egress-gateway-routes", def.InstallEgressGatewayRoutes, "Install egress gateway IP rules and routes in order to properly steer egress gateway traffic to the correct ENI interface")
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	lock.Mutex

	// cacheStatus is used to check if the agent has synced its
	// cache with the k8s API server
	cacheStatus k8s.CacheStatus

	// nodeDataStore stores node name to node mapping
	nodeDataStore map[string]nodeTypes.Node

	// nodes stores nodes sorted by their name
	nodes []nodeTypes.Node

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// policyConfigsBySourceIP stores slices of policy configs indexed by
	// the policies' source/endpoint IPs
	policyConfigsBySourceIP map[string][]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// installRoutes indicates if the manager should install additional IP
	// routes/rules to steer egress gateway traffic to the correct interface
	// with the egress IP assigned to
	installRoutes bool

	// policyMap communicates the active policies to the dapath.
	policyMap egressmap.PolicyMap
}

type Params struct {
	cell.In

	Config            Config
	DaemonConfig      *option.DaemonConfig
	CacheStatus       k8s.CacheStatus
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap         egressmap.PolicyMap

	Lifecycle hive.Lifecycle
}

func NewEgressGatewayManager(p Params) *Manager {
	if !p.DaemonConfig.EnableIPv4EgressGateway {
		return nil
	}

	manager := &Manager{
		cacheStatus:             p.CacheStatus,
		nodeDataStore:           make(map[string]nodeTypes.Node),
		policyConfigs:           make(map[policyID]*PolicyConfig),
		policyConfigsBySourceIP: make(map[string][]*PolicyConfig),
		epDataStore:             make(map[endpointID]*endpointMetadata),
		identityAllocator:       p.IdentityAllocator,
		installRoutes:           p.Config.InstallEgressGatewayRoutes,
		policyMap:               p.PolicyMap,
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			if probes.HaveLargeInstructionLimit() != nil {
				return fmt.Errorf("egress gateway needs kernel 5.2 or newer")
			}

			manager.runReconciliationAfterK8sSync(ctx)
			return nil
		},
		OnStop: func(hc hive.HookContext) error {
			cancel()
			return nil
		},
	})

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
func (manager *Manager) runReconciliationAfterK8sSync(ctx context.Context) {
	go func() {
		select {
		case <-manager.cacheStatus:
			manager.Lock()
			manager.reconcile(eventK8sSyncDone)
			manager.Unlock()
		case <-ctx.Done():
		}
	}()
}

// Event handlers

// OnAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) OnAddEgressPolicy(config PolicyConfig) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, config.id.Name)

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Debug("Added CiliumEgressGatewayPolicy")
	} else {
		logger.Debug("Updated CiliumEgressGatewayPolicy")
	}

	config.updateMatchedEndpointIDs(manager.epDataStore)

	manager.policyConfigs[config.id] = &config

	manager.reconcile(eventAddPolicy)
}

// OnDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (manager *Manager) OnDeleteEgressPolicy(configID policyID) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete CiliumEgressGatewayPolicy: policy not found")
		return
	}

	logger.Debug("Deleted CiliumEgressGatewayPolicy")

	delete(manager.policyConfigs, configID)

	manager.reconcile(eventDeletePolicy)
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
			Error("Failed to get identity labels for endpoint, skipping update to egress policy.")
		return
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return
	}

	manager.epDataStore[epData.id] = epData

	manager.reconcile(eventUpdateEndpoint)
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

	manager.reconcile(eventDeleteEndpoint)
}

// OnUpdateNode is the event handler for node additions and updates.
func (manager *Manager) OnUpdateNode(node nodeTypes.Node) {
	manager.Lock()
	defer manager.Unlock()
	manager.nodeDataStore[node.Name] = node
	manager.onChangeNodeLocked(eventUpdateNode)
}

// OnDeleteNode is the event handler for node deletions.
func (manager *Manager) OnDeleteNode(node nodeTypes.Node) {
	manager.Lock()
	defer manager.Unlock()
	delete(manager.nodeDataStore, node.Name)
	manager.onChangeNodeLocked(eventDeleteNode)
}

func (manager *Manager) onChangeNodeLocked(e eventType) {
	manager.nodes = []nodeTypes.Node{}
	for _, n := range manager.nodeDataStore {
		manager.nodes = append(manager.nodes, n)
	}
	sort.Slice(manager.nodes, func(i, j int) bool {
		return manager.nodes[i].Name < manager.nodes[j].Name
	})
	manager.reconcile(e)
}

func (manager *Manager) updatePoliciesMatchedEndpointIDs() {
	for _, policy := range manager.policyConfigs {
		policy.updateMatchedEndpointIDs(manager.epDataStore)
	}
}

func (manager *Manager) updatePoliciesBySourceIP() {
	manager.policyConfigsBySourceIP = make(map[string][]*PolicyConfig)

	for _, policy := range manager.policyConfigs {
		for _, ep := range policy.matchedEndpoints {
			for _, epIP := range ep.ips {
				ip := epIP.String()
				manager.policyConfigsBySourceIP[ip] = append(manager.policyConfigsBySourceIP[ip], policy)
			}
		}
	}
}

// policyMatches returns true if there exists at least one policy matching the
// given parameters.
//
// This method takes:
//   - a source IP: this is an optimization that allows to iterate only through
//     policies that reference an endpoint with the given source IP
//   - a callback function f: this function is invoked for each policy and for
//     each combination of the policy's endpoints and destination/excludedCIDRs.
//
// The callback f takes as arguments:
// - the given endpoint
// - the destination CIDR
// - a boolean value indicating if the CIDR belongs to the excluded ones
// - the gatewayConfig of the  policy
//
// This method returns true whenever the f callback matches one of the endpoint
// and CIDR tuples (i.e. whenever one callback invocation returns true)
func (manager *Manager) policyMatches(sourceIP net.IP, f func(net.IP, *net.IPNet, bool, *gatewayConfig) bool) bool {
	for _, policy := range manager.policyConfigsBySourceIP[sourceIP.String()] {
		for _, ep := range policy.matchedEndpoints {
			for _, endpointIP := range ep.ips {
				if !endpointIP.Equal(sourceIP) {
					continue
				}

				isExcludedCIDR := false
				for _, dstCIDR := range policy.dstCIDRs {
					if f(endpointIP, dstCIDR, isExcludedCIDR, &policy.gatewayConfig) {
						return true
					}
				}

				isExcludedCIDR = true
				for _, excludedCIDR := range policy.excludedCIDRs {
					if f(endpointIP, excludedCIDR, isExcludedCIDR, &policy.gatewayConfig) {
						return true
					}
				}
			}
		}
	}

	return false
}

// policyMatchesMinusExcludedCIDRs returns true if there exists at least one
// policy matching the given parameters.
//
// This method takes:
//   - a source IP: this is an optimization that allows to iterate only through
//     policies that reference an endpoint with the given source IP
//   - a callback function f: this function is invoked for each policy and for
//     each combination of the policy's endpoints and computed destinations (i.e.
//     the effective destination CIDR space, defined as the diff between the
//     destination and the excluded CIDRs).
//
// The callback f takes as arguments:
// - the given endpoint
// - the destination CIDR
// - the gatewayConfig of the  policy
//
// This method returns true whenever the f callback matches one of the endpoint
// and CIDR tuples (i.e. whenever one callback invocation returns true)
func (manager *Manager) policyMatchesMinusExcludedCIDRs(sourceIP net.IP, f func(net.IP, *net.IPNet, *gatewayConfig) bool) bool {
	for _, policy := range manager.policyConfigsBySourceIP[sourceIP.String()] {
		cidrs := policy.destinationMinusExcludedCIDRs()

		for _, ep := range policy.matchedEndpoints {
			for _, endpointIP := range ep.ips {
				if !endpointIP.Equal(sourceIP) {
					continue
				}

				for _, cidr := range cidrs {
					if f(endpointIP, cidr, &policy.gatewayConfig) {
						return true
					}
				}
			}
		}
	}

	return false
}

func (manager *Manager) regenerateGatewayConfigs() {
	for _, policyConfig := range manager.policyConfigs {
		policyConfig.regenerateGatewayConfig(manager)
	}
}

func (manager *Manager) addMissingIpRulesAndRoutes(isRetry bool) (shouldRetry bool) {
	if !manager.installRoutes {
		return false
	}

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

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndDestination(addIPRulesAndRoutesForConfig)
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
			if !manager.installRoutes {
				return false
			}

			if !gwc.localNodeConfiguredAsGateway {
				return false
			}

			// no need to check also ipRule.Src.IP.Equal(endpointIP) as we are iterating
			// over the slice of policies returned by the
			// policyConfigsBySourceIP[ipRule.Src.IP.String()] map
			return ipRule.Dst.String() == dstCIDR.String()
		}

		if manager.policyMatchesMinusExcludedCIDRs(ipRule.Src.IP, matchFunc) {
			continue nextIpRule
		}

		deleteIpRule(ipRule)
	}

	// Build a list of all the network interfaces that are being actively used by egress gateway
	activeEgressGwIfaceIndexes := map[int]struct{}{}
	for _, policyConfig := range manager.policyConfigs {
		// check if the policy selects at least one endpoint
		if len(policyConfig.matchedEndpoints) != 0 {
			if policyConfig.gatewayConfig.localNodeConfiguredAsGateway {
				activeEgressGwIfaceIndexes[policyConfig.gatewayConfig.ifaceIndex] = struct{}{}
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
	manager.policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	addEgressRule := func(endpointIP net.IP, dstCIDR *net.IPNet, excludedCIDR bool, gwc *gatewayConfig) {
		policyKey := egressmap.NewEgressPolicyKey4(endpointIP, dstCIDR.IP, dstCIDR.Mask)
		policyVal, policyPresent := egressPolicies[policyKey]

		gatewayIP := gwc.gatewayIP
		if excludedCIDR {
			gatewayIP = ExcludedCIDRIPv4
		}

		if policyPresent && policyVal.Match(gwc.egressIP.IP, gatewayIP) {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        endpointIP,
			logfields.DestinationCIDR: dstCIDR.String(),
			logfields.EgressIP:        gwc.egressIP.IP,
			logfields.GatewayIP:       gatewayIP,
		})

		if err := manager.policyMap.Update(endpointIP, *dstCIDR, gwc.egressIP.IP, gatewayIP); err != nil {
			logger.WithError(err).Error("Error applying egress gateway policy")
		} else {
			logger.Debug("Egress gateway policy applied")
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndCIDR(addEgressRule)
	}
}

// removeUnusedEgressRules is responsible for removing any entry in the egress policy BPF map which
// is not baked by an actual k8s CiliumEgressGatewayPolicy.
func (manager *Manager) removeUnusedEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

nextPolicyKey:
	for policyKey, policyVal := range egressPolicies {
		matchPolicy := func(endpointIP net.IP, dstCIDR *net.IPNet, excludedCIDR bool, gwc *gatewayConfig) bool {
			gatewayIP := gwc.gatewayIP
			if excludedCIDR {
				gatewayIP = ExcludedCIDRIPv4
			}

			return policyKey.Match(endpointIP, dstCIDR) && policyVal.Match(gwc.egressIP.IP, gatewayIP)
		}

		if manager.policyMatches(policyKey.SourceIP.IP(), matchPolicy) {
			continue nextPolicyKey
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        policyKey.GetSourceIP(),
			logfields.DestinationCIDR: policyKey.GetDestCIDR().String(),
			logfields.EgressIP:        policyVal.GetEgressIP(),
			logfields.GatewayIP:       policyVal.GetGatewayIP(),
		})

		if err := manager.policyMap.Delete(policyKey.GetSourceIP(), *policyKey.GetDestCIDR()); err != nil {
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
func (manager *Manager) reconcile(e eventType) {
	if !manager.cacheStatus.Synchronized() {
		return
	}

	switch e {
	case eventUpdateEndpoint, eventDeleteEndpoint:
		manager.updatePoliciesMatchedEndpointIDs()
		manager.updatePoliciesBySourceIP()
	case eventAddPolicy, eventDeletePolicy:
		manager.updatePoliciesBySourceIP()

	// on eventK8sSyncDone we need to update all caches unconditionally as
	// we don't know which k8s events/resources were received during the
	// initial k8s sync
	case eventK8sSyncDone:
		manager.updatePoliciesMatchedEndpointIDs()
		manager.updatePoliciesBySourceIP()
	}

	manager.regenerateGatewayConfigs()

	shouldRetry := manager.addMissingIpRulesAndRoutes(false)
	manager.removeUnusedIpRulesAndRoutes()

	if shouldRetry {
		manager.addMissingIpRulesAndRoutes(true)
	}

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingEgressRules()
	manager.removeUnusedEgressRules()
}

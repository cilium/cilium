// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	// GatewayNotFoundIPv4 is a special IP value used as gatewayIP in the BPF policy
	// map to indicate no gateway was found for the given policy
	GatewayNotFoundIPv4 = netip.IPv4Unspecified()
	// ExcludedCIDRIPv4 is a special IP value used as gatewayIP in the BPF policy map
	// to indicate the entry is for an excluded CIDR and should skip egress gateway
	ExcludedCIDRIPv4 = netip.MustParseAddr("0.0.0.1")
	// EgressIPNotFoundIPv4 is a special IP value used as egressIP in the BPF policy map
	// to indicate no egressIP was found for the given policy
	EgressIPNotFoundIPv4 = netip.IPv4Unspecified()

	// IPv6 special values
	// GatewayNotFoundIPv6 is a special IP value used as gatewayIP in the BPF policy
	// map to indicate no gateway was found for the given policy
	GatewayNotFoundIPv6 = netip.IPv6Unspecified()
	// ExcludedCIDRIPv6 is a special IP value used as gatewayIP in the BPF policy map
	// to indicate the entry is for an excluded CIDR and should skip egress gateway
	ExcludedCIDRIPv6 = netip.MustParseAddr("::1")
	// EgressIPNotFoundIPv6 is a special IP value used as egressIP in the BPF policy map
	// to indicate no egressIP was found for the given policy
	EgressIPNotFoundIPv6 = netip.IPv6Unspecified()
)

// Log field constants
const (
	logReasonFlag = "reasonFlag"
	logReason     = "reasonText"
	logFlagName   = "flagName"
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"egressgateway",
	"Egress Gateway allows originating traffic from specific IP addresses",
	cell.Config(defaultConfig),
	cell.Provide(NewEgressGatewayManager),
	cell.Provide(newPolicyResource),
	cell.Provide(func(dcfg *option.DaemonConfig) tunnel.EnablerOut {
		if !dcfg.EnableEgressGateway {
			return tunnel.EnablerOut{}
		}
		return tunnel.NewEnabler(true)
	}),
)

type eventType int

const (
	eventNone = eventType(1 << iota)
	eventK8sSyncDone
	eventAddPolicy
	eventDeletePolicy
	eventUpdateEndpoint
	eventDeleteEndpoint
	eventUpdateNode
	eventDeleteNode
)

type Config struct {
	// Default amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayReconciliationTriggerInterval time.Duration
}

var defaultConfig = Config{
	EgressGatewayReconciliationTriggerInterval: 1 * time.Second,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-reconciliation-trigger-interval", def.EgressGatewayReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
}

// IPFamilySupport tracks whether IPv4 and/or IPv6 egress gateway policies are supported
// Dual-stack environments will have both IPv4 and IPv6 fields set to true, allowing
// for egress gateway policies with either IPv4 or IPv6 CIDRs or a mix of both.
type IPFamilySupport struct {
	IPv4 bool // Whether IPv4 egress gateway policies are supported
	IPv6 bool // Whether IPv6 egress gateway policies are supported
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	logger *slog.Logger

	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// ipFamilySupport tracks which IP families are supported for egress gateway policies
	ipFamilySupport IPFamilySupport

	// nodes stores nodes sorted by their name. The entries are sorted
	// to ensure consistent gateway selection across all agents.
	nodes []nodeTypes.Node
	// nodesAddresses2Labels store the labels of each node so that the endpoint can match the node labels
	// key is the IP address of the node, and value is the labels of the node.
	nodesAddresses2Labels map[string]map[string]string
	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// nodesResource allows reading node CRD from k8s.
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode]

	// endpoints allows reading endpoint CRD from k8s.
	endpoints resource.Resource[*k8sTypes.CiliumEndpoint]

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// policyMap4 communicates the active IPv4 policies to the datapath.
	policyMap4 *egressmap.PolicyMap4

	// policyMap6 communicates the active IPv6 policies to the datapath.
	policyMap6 *egressmap.PolicyMap6

	// reconciliationTriggerInterval is the amount of time between triggers
	// of reconciliations are invoked
	reconciliationTriggerInterval time.Duration

	// eventsBitmap is a bitmap that tracks which type of events has been
	// received by the manager (e.g. node added or policy removed) since the
	// last invocation of the reconciliation logic
	eventsBitmap eventType

	// reconciliationTrigger is the trigger used to reconcile the state of
	// the node with the desired egress gateway state.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger

	// reconciliationEventsCount keeps track of how many reconciliation
	// events have occoured
	reconciliationEventsCount atomic.Uint64

	sysctl sysctl.Sysctl
}

type Params struct {
	cell.In

	Logger *slog.Logger

	Config            Config
	DaemonConfig      *option.DaemonConfig
	TunnelConfig      tunnel.Config
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap4        *egressmap.PolicyMap4
	PolicyMap6        *egressmap.PolicyMap6
	Policies          resource.Resource[*Policy]
	Nodes             resource.Resource[*cilium_api_v2.CiliumNode]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]
	Sysctl            sysctl.Sysctl

	Lifecycle cell.Lifecycle
}

func NewEgressGatewayManager(p Params) (out struct {
	cell.Out

	*Manager
	defines.NodeOut
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableEgressGateway {
		return out, nil
	}

	if dcfg.IdentityAllocationMode != option.IdentityAllocationModeCRD {
		return out, fmt.Errorf("egress gateway is not supported in %s identity allocation mode", dcfg.IdentityAllocationMode)
	}

	if dcfg.EnableCiliumEndpointSlice {
		return out, errors.New("egress gateway is not supported in combination with the CiliumEndpointSlice feature")
	}

	// Check which IP families are supported for egress gateway policies
	ipFamilySupport, err := determineIPFamilySupport(dcfg, p.TunnelConfig, p.Logger)
	if err != nil {
		return out, err
	}

	// Ensure at least one IP family is supported
	if !ipFamilySupport.IPv4 && !ipFamilySupport.IPv6 {
		return out, errors.New("egress gateway requires at least one supported IP family (IPv4 or IPv6). " +
			"Make sure masquerading is enabled with BPF implementation.")
	}

	out.Manager, err = newEgressGatewayManager(p, ipFamilySupport)
	if err != nil {
		return out, err
	}

	out.NodeDefines = map[string]string{
		"ENABLE_EGRESS_GATEWAY": "1",
	}

	return out, nil
}

func newEgressGatewayManager(p Params, ipFamilySupport IPFamilySupport) (*Manager, error) {
	manager := &Manager{
		logger:                        p.Logger,
		ipFamilySupport:               ipFamilySupport,
		policyConfigs:                 make(map[policyID]*PolicyConfig),
		epDataStore:                   make(map[endpointID]*endpointMetadata),
		identityAllocator:             p.IdentityAllocator,
		reconciliationTriggerInterval: p.Config.EgressGatewayReconciliationTriggerInterval,
		policyMap4:                    p.PolicyMap4,
		policyMap6:                    p.PolicyMap6,
		policies:                      p.Policies,
		ciliumNodes:                   p.Nodes,
		endpoints:                     p.Endpoints,
		sysctl:                        p.Sysctl,
		nodesAddresses2Labels:         make(map[string]map[string]string),
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "egress_gateway_reconciliation",
		MinInterval: p.Config.EgressGatewayReconciliationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			manager.logger.Debug("reconciliation triggered", logfields.Reasons, reasons)

			manager.Lock()
			defer manager.Unlock()

			manager.reconcileLocked()
		},
	})
	if err != nil {
		return nil, err
	}

	manager.reconciliationTrigger = t

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			wg.Add(1)
			go func() {
				defer wg.Done()
				manager.processEvents(ctx)
			}()

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()

			wg.Wait()
			return nil
		},
	})

	return manager, nil
}

func (manager *Manager) setEventBitmap(events ...eventType) {
	for _, e := range events {
		manager.eventsBitmap |= e
	}
}

func (manager *Manager) eventBitmapIsSet(events ...eventType) bool {
	for _, e := range events {
		if manager.eventsBitmap&e != 0 {
			return true
		}
	}

	return false
}

// getIdentityLabels waits for the global identities to be populated to the cache,
// then looks up identity by ID from the cached identity allocator and return its labels.
func (manager *Manager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	if err := manager.identityAllocator.WaitForInitialGlobalIdentities(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %w", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// processEvents spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) processEvents(ctx context.Context) {
	var policySync, nodeSync, endpointSync bool
	maybeTriggerReconcile := func() {
		if !policySync || !nodeSync || !endpointSync {
			return
		}

		manager.Lock()
		defer manager.Unlock()

		if manager.allCachesSynced {
			return
		}

		manager.allCachesSynced = true
		manager.setEventBitmap(eventK8sSyncDone)
		manager.reconciliationTrigger.TriggerWithReason("k8s sync done")
	}

	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	endpointsRateLimit := workqueue.NewTypedItemExponentialFailureRateLimiter[resource.WorkItem](
		time.Millisecond*20,
		time.Minute*20,
	)

	policyEvents := manager.policies.Events(ctx)
	nodeEvents := manager.ciliumNodes.Events(ctx)
	endpointEvents := manager.endpoints.Events(ctx, resource.WithRateLimiter(endpointsRateLimit))

	for {
		select {
		case <-ctx.Done():
			return

		case event := <-policyEvents:
			if event.Kind == resource.Sync {
				policySync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handlePolicyEvent(event)
			}

		case event := <-nodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleNodeEvent(event)
			}

		case event := <-endpointEvents:
			if event.Kind == resource.Sync {
				endpointSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleEndpointEvent(event)
			}
		}
	}
}

func (manager *Manager) handlePolicyEvent(event resource.Event[*Policy]) {
	switch event.Kind {
	case resource.Upsert:
		err := manager.onAddEgressPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		manager.onDeleteEgressPolicy(event.Object)
		event.Done(nil)
	}
}

// Event handlers

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) onAddEgressPolicy(policy *Policy) error {

	config, err := ParseCEGP(policy)
	if err != nil {
		manager.logger.Warn(
			"Failed to parse CiliumEgressGatewayPolicy",
			logfields.Error, err,
			logfields.CiliumEgressGatewayPolicyName, policy.Name,
		)
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	// Validate that the policy only uses supported IP families
	if err := manager.validatePolicyAgainstSupportedFamilies(config); err != nil {
		manager.logger.Warn(
			"Failed to validate CiliumEgressGatewayPolicy",
			logfields.Error, err,
			logfields.CiliumEgressGatewayPolicyName, policy.Name,
		)
		return err
	}

	if _, ok := manager.policyConfigs[config.id]; !ok {
		manager.logger.Debug(
			"Added CiliumEgressGatewayPolicy",
			logfields.CiliumEgressGatewayPolicyName, policy.Name,
		)
	} else {
		manager.logger.Debug(
			"Updated CiliumEgressGatewayPolicy",
			logfields.CiliumEgressGatewayPolicyName, policy.Name,
		)
	}

	config.updateMatchedEndpointIDs(manager.epDataStore, manager.nodesAddresses2Labels)

	manager.policyConfigs[config.id] = config

	manager.setEventBitmap(eventAddPolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy added")
	return nil
}

// onDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (manager *Manager) onDeleteEgressPolicy(policy *Policy) {
	configID := ParseCEGPConfigID(policy)

	manager.Lock()
	defer manager.Unlock()

	if manager.policyConfigs[configID] == nil {
		manager.logger.Warn(
			"Can't delete CiliumEgressGatewayPolicy: policy not found",
			logfields.CiliumEgressGatewayPolicyName, policy.Name,
		)
	}

	manager.logger.Debug(
		"Deleted CiliumEgressGatewayPolicy",
		logfields.CiliumEgressGatewayPolicyName, policy.Name,
	)

	delete(manager.policyConfigs, configID)

	manager.setEventBitmap(eventDeletePolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy deleted")
}

func (manager *Manager) addEndpoint(endpoint *k8sTypes.CiliumEndpoint) error {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

	manager.Lock()
	defer manager.Unlock()

	logger := manager.logger.With(
		logfields.K8sEndpointName, endpoint.Name,
		logfields.K8sNamespace, endpoint.Namespace,
		logfields.K8sUID, endpoint.UID,
	)

	if endpoint.Identity == nil {
		logger.Warn(
			"Endpoint is missing identity metadata, skipping update to egress policy.",
		)
		return nil
	}

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.Warn(
			"Failed to get identity labels for endpoint",
			logfields.Error, err,
		)
		return err
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.Error(
			"Failed to get valid endpoint metadata, skipping update to egress policy.",
			logfields.Error, err,
		)
		return nil
	}

	if _, ok := manager.epDataStore[epData.id]; ok {
		logger.Debug(
			"Updated CiliumEndpoint",
			logfields.Error, err,
		)
	} else {
		logger.Debug(
			"Added CiliumEndpoint",
			logfields.Error, err,
		)
	}

	manager.epDataStore[epData.id] = epData

	manager.setEventBitmap(eventUpdateEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint updated")

	return nil
}

func (manager *Manager) deleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.Lock()
	defer manager.Unlock()

	manager.logger.Debug(
		"Deleted CiliumEndpoint",
		logfields.K8sEndpointName, endpoint.Name,
		logfields.K8sNamespace, endpoint.Namespace,
		logfields.K8sUID, endpoint.UID,
	)
	delete(manager.epDataStore, endpoint.UID)

	manager.setEventBitmap(eventDeleteEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint deleted")
}

func (manager *Manager) handleEndpointEvent(event resource.Event[*k8sTypes.CiliumEndpoint]) {
	endpoint := event.Object

	if event.Kind == resource.Upsert {
		event.Done(manager.addEndpoint(endpoint))
	} else {
		manager.deleteEndpoint(endpoint)
		event.Done(nil)
	}
}

// handleNodeEvent takes care of node upserts and removals.
func (manager *Manager) handleNodeEvent(event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	node := nodeTypes.ParseCiliumNode(event.Object)

	manager.Lock()
	defer manager.Unlock()

	// Find the node if we already have it.
	nidx, found := slices.BinarySearchFunc(manager.nodes, node, func(a nodeTypes.Node, b nodeTypes.Node) int {
		return cmp.Compare(a.Name, b.Name)
	})

	if event.Kind == resource.Delete {
		// Delete the node if we're aware of it.
		if found {
			delete(manager.nodesAddresses2Labels, node.GetNodeIP(false).String()) // for ipv4
			delete(manager.nodesAddresses2Labels, node.GetNodeIP(true).String())  // for ipv6
			manager.nodes = slices.Delete(manager.nodes, nidx, nidx+1)
		}

		manager.setEventBitmap(eventDeleteNode)
		manager.reconciliationTrigger.TriggerWithReason("node deleted")
		return
	}

	// Update the node if we have it, otherwise insert in the correct
	// position.
	if found {
		manager.nodes[nidx] = node
	} else {
		manager.nodes = slices.Insert(manager.nodes, nidx, node)
	}
	// We need to store the labels of each node so that the endpoint can match the node labels
	manager.nodesAddresses2Labels[node.GetNodeIP(false).String()] = node.Labels // for ipv4
	manager.nodesAddresses2Labels[node.GetNodeIP(true).String()] = node.Labels  // for ipv6
	manager.setEventBitmap(eventUpdateNode)
	manager.reconciliationTrigger.TriggerWithReason("node updated")
}

func (manager *Manager) updatePoliciesMatchedEndpointIDs() {
	for _, policy := range manager.policyConfigs {
		policy.updateMatchedEndpointIDs(manager.epDataStore, manager.nodesAddresses2Labels)
	}
}

func (manager *Manager) regenerateGatewayConfigs() {
	for _, policyConfig := range manager.policyConfigs {
		policyConfig.regenerateGatewayConfig(manager)
	}
}

func (manager *Manager) relaxRPFilter() error {
	// rp_filter is an IPv4-specific setting, so we only need to do this if IPv4 is supported
	if !manager.ipFamilySupport.IPv4 {
		return nil
	}

	var sysSettings []tables.Sysctl
	ifSet := make(map[string]struct{})

	for _, pc := range manager.policyConfigs {
		for _, gatewayConfig := range pc.gatewayConfigs {
			if !gatewayConfig.localNodeConfiguredAsGateway {
				continue
			}

			ifaceName := gatewayConfig.ifaceName
			if _, ok := ifSet[ifaceName]; !ok {
				ifSet[ifaceName] = struct{}{}
				sysSettings = append(sysSettings, tables.Sysctl{
					Name:      []string{"net", "ipv4", "conf", ifaceName, "rp_filter"},
					Val:       "2",
					IgnoreErr: false,
				})
			}
		}
	}

	if len(sysSettings) == 0 {
		return nil
	}

	return manager.sysctl.ApplySettings(sysSettings)
}

func (manager *Manager) updateEgressRules4() {
	if manager.policyMap4 == nil || !manager.ipFamilySupport.IPv4 {
		return
	}

	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	manager.policyMap4.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	// Start with the assumption that all the entries currently present in the
	// BPF map are stale. Then as we walk the entries below and discover which
	// entries are actually still needed, shrink this set down.
	stale := sets.KeySet(egressPolicies)

	addEgressRule := func(endpointIP netip.Addr, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) {
		if !endpointIP.Is4() || !dstCIDR.Addr().Is4() {
			return
		}

		policyKey := egressmap.NewEgressPolicyKey4(endpointIP, dstCIDR)
		// This key needs to be present in the BPF map, hence remove it from
		// the list of stale ones.
		stale.Delete(policyKey)

		policyVal, policyPresent := egressPolicies[policyKey]

		gatewayIP := gwc.gatewayIP
		if excludedCIDR {
			gatewayIP = ExcludedCIDRIPv4
		}

		if policyPresent && policyVal.Match(gwc.egressIP4, gatewayIP) {
			return
		}

		if err := manager.policyMap4.Update(endpointIP, dstCIDR, gwc.egressIP4, gatewayIP); err != nil {
			manager.logger.Error(
				"Error applying IPv4 egress gateway policy",
				logfields.Error, err,
				logfields.SourceIP, endpointIP,
				logfields.DestinationCIDR, dstCIDR,
				logfields.EgressIP, gwc.egressIP4,
				logfields.GatewayIP, gatewayIP,
			)
		} else {
			manager.logger.Debug("IPv4 egress gateway policy applied",
				logfields.SourceIP, endpointIP,
				logfields.DestinationCIDR, dstCIDR,
				logfields.EgressIP, gwc.egressIP4,
				logfields.GatewayIP, gatewayIP,
			)
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndCIDR(addEgressRule)
	}

	// Remove all the entries marked as stale.
	for policyKey := range stale {
		if err := manager.policyMap4.Delete(policyKey.GetSourceIP(), policyKey.GetDestCIDR()); err != nil {
			manager.logger.Error(
				"Error removing IPv4 egress gateway policy",
				logfields.Error, err,
				logfields.SourceIP, policyKey.GetSourceIP(),
				logfields.DestinationCIDR, policyKey.GetDestCIDR(),
			)
		} else {
			manager.logger.Debug(
				"IPv4 egress gateway policy removed",
				logfields.SourceIP, policyKey.GetSourceIP(),
				logfields.DestinationCIDR, policyKey.GetDestCIDR(),
			)
		}
	}
}

func (manager *Manager) updateEgressRules6() {
	if manager.policyMap6 == nil || !manager.ipFamilySupport.IPv6 {
		return
	}

	egressPolicies := map[egressmap.EgressPolicyKey6]egressmap.EgressPolicyVal6{}
	manager.policyMap6.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey6, val *egressmap.EgressPolicyVal6) {
			egressPolicies[*key] = *val
		})

	// Start with the assumption that all the entries currently present in the
	// BPF maps are stale. Then as we walk the entries below and discover which
	// entries are actually still needed, shrink these sets down.
	stale := sets.KeySet(egressPolicies)

	addEgressRule := func(endpointIP netip.Addr, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) {
		if !endpointIP.Is6() || !dstCIDR.Addr().Is6() {
			return
		}

		policyKey := egressmap.NewEgressPolicyKey6(endpointIP, dstCIDR)
		// This key needs to be present in the BPF map, hence remove it from
		// the list of stale ones.
		stale.Delete(policyKey)

		policyVal, policyPresent := egressPolicies[policyKey]

		gatewayIP := gwc.gatewayIP
		if excludedCIDR {
			gatewayIP = ExcludedCIDRIPv6
		}

		if policyPresent && policyVal.Match(gwc.egressIP6, gatewayIP) {
			return
		}

		if err := manager.policyMap6.Update(endpointIP, dstCIDR, gwc.egressIP6, gatewayIP); err != nil {
			manager.logger.Error(
				"Error applying IPv6 egress gateway policy",
				logfields.Error, err,
				logfields.SourceIP, endpointIP,
				logfields.DestinationCIDR, dstCIDR,
				logfields.EgressIP, gwc.egressIP6,
				logfields.GatewayIP, gatewayIP,
			)
		} else {
			manager.logger.Debug("IPv6 egress gateway policy applied",
				logfields.SourceIP, endpointIP,
				logfields.DestinationCIDR, dstCIDR,
				logfields.EgressIP, gwc.egressIP6,
				logfields.GatewayIP, gatewayIP,
			)
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndCIDR(addEgressRule)
	}

	for policyKey := range stale {
		if err := manager.policyMap6.Delete(policyKey.GetSourceIP(), policyKey.GetDestCIDR()); err != nil {
			manager.logger.Error(
				"Error removing IPv6 egress gateway policy",
				logfields.Error, err,
				logfields.SourceIP, policyKey.GetSourceIP(),
				logfields.DestinationCIDR, policyKey.GetDestCIDR(),
			)
		} else {
			manager.logger.Debug(
				"IPv6 egress gateway policy removed",
				logfields.SourceIP, policyKey.GetSourceIP(),
				logfields.DestinationCIDR, policyKey.GetDestCIDR(),
			)
		}
	}
}

// determineIPFamilySupport checks the daemon configuration and tunnel configuration
// to determine which IP families (IPv4, IPv6) are supported for egress gateway policies.
// It returns an IPFamilySupport structure indicating which families are supported.
// In dual-stack environments, both IPv4 and IPv6 can be supported simultaneously.
func determineIPFamilySupport(dcfg *option.DaemonConfig, tunnelConfig tunnel.Config, logger *slog.Logger) (IPFamilySupport, error) {
	var support IPFamilySupport

	// Check for IPv4 support
	if dcfg.EnableIPv4 {
		ipv4Requirements := []struct {
			condition bool
			reason    string
			flag      string
		}{
			{condition: dcfg.EnableIPv4Masquerade, reason: "IPv4 masquerading is not enabled", flag: option.EnableIPv4Masquerade},
			{condition: dcfg.EnableBPFMasquerade, reason: "BPF masquerading is not enabled", flag: option.EnableBPFMasquerade},
		}

		ipv4Supported := true
		for _, req := range ipv4Requirements {
			if !req.condition {
				ipv4Supported = false
				if req.flag != "" {
					logger.Info("IPv4 egress gateway policies requirement not met",
						logReason, req.reason,
						logFlagName, req.flag)
				} else {
					logger.Info("IPv4 egress gateway policies requirement not met",
						logReason, req.reason)
				}
			}
		}

		// Check tunnel configuration for IPv4
		if tunnelConfig.UnderlayProtocol() != tunnel.IPv4 {
			ipv4Supported = false
			logger.Info("IPv4 egress gateway policies requirement not met",
				logReason, "tunnel underlay protocol is not IPv4")
		}

		support.IPv4 = ipv4Supported
		if ipv4Supported {
			logger.Info("IPv4 egress gateway policies are enabled")
		}
	} else {
		logger.Info("IPv4 egress gateway policies are disabled because IPv4 is not enabled",
			logFlagName, option.EnableIPv4Name)
	}

	// Check for IPv6 support
	if dcfg.EnableIPv6 {
		ipv6Requirements := []struct {
			condition bool
			reason    string
			flag      string
		}{
			{condition: dcfg.EnableIPv6Masquerade, reason: "IPv6 masquerading is not enabled", flag: option.EnableIPv6Masquerade},
			{condition: dcfg.EnableBPFMasquerade, reason: "BPF masquerading is not enabled", flag: option.EnableBPFMasquerade},
		}

		ipv6Supported := true
		for _, req := range ipv6Requirements {
			if !req.condition {
				ipv6Supported = false
				if req.flag != "" {
					logger.Info("IPv6 egress gateway policies requirement not met",
						logReason, req.reason,
						logFlagName, req.flag)
				} else {
					logger.Info("IPv6 egress gateway policies requirement not met",
						logReason, req.reason)
				}
			}
		}

		support.IPv6 = ipv6Supported
		if ipv6Supported {
			logger.Info("IPv6 egress gateway policies are enabled")
		}
	} else {
		logger.Info("IPv6 egress gateway policies are disabled because IPv6 is not enabled",
			logFlagName, option.EnableIPv6Name)
	}

	// Log a summary of the IP family support for egress gateway
	if support.IPv4 && support.IPv6 {
		logger.Info("Egress gateway is enabled for dual-stack (IPv4 and IPv6)")
	} else if support.IPv4 {
		logger.Info("Egress gateway is enabled for IPv4 only")
	} else if support.IPv6 {
		logger.Info("Egress gateway is enabled for IPv6 only")
	} else {
		logger.Info("Egress gateway is not enabled for any IP family")
	}

	return support, nil
}

// reconcileLocked is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (egress policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcileLocked() {
	if !manager.allCachesSynced {
		return
	}

	switch {
	// on eventK8sSyncDone we need to update all caches unconditionally as
	// we don't know which k8s events/resources were received during the
	// initial k8s sync
	case manager.eventBitmapIsSet(eventUpdateEndpoint, eventDeleteEndpoint, eventUpdateNode, eventDeleteNode, eventK8sSyncDone):
		manager.updatePoliciesMatchedEndpointIDs()
	}

	if manager.eventBitmapIsSet(eventK8sSyncDone, eventAddPolicy, eventDeletePolicy, eventUpdateNode, eventDeleteNode) {
		manager.regenerateGatewayConfigs()

		// Sysctl updates are handled by a reconciler, with the initial update attempting to wait some time
		// for a synchronous reconciliation. Thus these updates are already resilient so in case of failure
		// our best course of action is to log the error and continue with the reconciliation.
		//
		// The rp_filter setting is only important for traffic originating from endpoints on the same host (i.e.
		// egw traffic being forwarded from a local Pod endpoint to the gateway on the same node).
		// Therefore, for the sake of resiliency, it is acceptable for EGW to continue reconciling gatewayConfigs
		// even if the rp_filter setting are failing.
		if err := manager.relaxRPFilter(); err != nil {
			manager.logger.Error(
				"Error relaxing rp_filter for gateway interfaces. "+
					"Selected egress gateway interfaces require rp_filter settings to use loose mode (rp_filter=2) for gateway forwarding to work correctly. "+
					"This may cause connectivity issues for egress gateway traffic being forwarded through this node for Pods running on the same host. ",
				logfields.Error, err,
			)
		}
	}

	// Update the content of the BPF maps based on supported IP families
	if manager.ipFamilySupport.IPv4 {
		manager.updateEgressRules4()
	}

	if manager.ipFamilySupport.IPv6 {
		manager.updateEgressRules6()
	}

	// clear the events bitmap
	manager.eventsBitmap = 0

	manager.reconciliationEventsCount.Add(1)
}

// validatePolicyAgainstSupportedFamilies checks if the policy's destination CIDRs
// are compatible with the supported IP families. Returns an error if any CIDR
// uses an unsupported IP family.
func (manager *Manager) validatePolicyAgainstSupportedFamilies(config *PolicyConfig) error {
	// Check if the policy has IPv4 CIDRs but IPv4 is not supported
	if !manager.ipFamilySupport.IPv4 {
		for _, cidr := range config.dstCIDRs {
			if cidr.Addr().Is4() {
				return fmt.Errorf("policy %q contains IPv4 CIDR %q but IPv4 egress gateway is not supported with current configuration",
					config.id, cidr.String())
			}
		}
		for _, cidr := range config.excludedCIDRs {
			if cidr.Addr().Is4() {
				return fmt.Errorf("policy %q contains IPv4 excluded CIDR %q but IPv4 egress gateway is not supported with current configuration",
					config.id, cidr.String())
			}
		}
	}

	// Check if the policy has IPv6 CIDRs but IPv6 is not supported
	if !manager.ipFamilySupport.IPv6 {
		for _, cidr := range config.dstCIDRs {
			if cidr.Addr().Is6() {
				return fmt.Errorf("policy %q contains IPv6 CIDR %q but IPv6 egress gateway is not supported with current configuration",
					config.id, cidr.String())
			}
		}
		for _, cidr := range config.excludedCIDRs {
			if cidr.Addr().Is6() {
				return fmt.Errorf("policy %q contains IPv6 excluded CIDR %q but IPv6 egress gateway is not supported with current configuration",
					config.id, cidr.String())
			}
		}
	}

	return nil
}

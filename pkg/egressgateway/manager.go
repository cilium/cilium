// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
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
	cell.Provide(newPolicyResource),
)

type eventType int

const (
	eventNone = eventType(1 << iota)
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

	// Default amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayReconciliationTriggerInterval time.Duration
}

var defaultConfig = Config{
	InstallEgressGatewayRoutes:                 false,
	EgressGatewayReconciliationTriggerInterval: 1 * time.Second,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("install-egress-gateway-routes", def.InstallEgressGatewayRoutes, "Install egress gateway IP rules and routes in order to properly steer egress gateway traffic to the correct ENI interface")
	flags.Duration("egress-gateway-reconciliation-trigger-interval", def.EgressGatewayReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// nodeDataStore stores node name to node mapping
	nodeDataStore map[string]nodeTypes.Node

	// nodes stores nodes sorted by their name
	nodes []nodeTypes.Node

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// policyConfigsBySourceIP stores slices of policy configs indexed by
	// the policies' source/endpoint IPs
	policyConfigsBySourceIP map[string][]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// pendingEndpointEvents stores the k8s CiliumEndpoint add/update events
	// which still need to be processed by the manager, either because we
	// just received the event, or because the processing failed due to the
	// manager being unable to resolve the endpoint identity to a set of
	// labels
	pendingEndpointEvents map[endpointID]*k8sTypes.CiliumEndpoint

	// pendingEndpointEventsLock protects the access to the
	// pendingEndpointEvents map
	pendingEndpointEventsLock lock.RWMutex

	// endpointEventsQueue is a workqueue of CiliumEndpoint IDs that need to
	// be processed by the manager
	endpointEventsQueue workqueue.RateLimitingInterface

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// installRoutes indicates if the manager should install additional IP
	// routes/rules to steer egress gateway traffic to the correct interface
	// with the egress IP assigned to
	installRoutes bool

	// policyMap communicates the active policies to the dapath.
	policyMap egressmap.PolicyMap

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
}

type Params struct {
	cell.In

	Config            Config
	DaemonConfig      *option.DaemonConfig
	CacheStatus       k8s.CacheStatus
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap         egressmap.PolicyMap
	Policies          resource.Resource[*Policy]

	Lifecycle hive.Lifecycle
}

func NewEgressGatewayManager(p Params) (out struct {
	cell.Out

	*Manager
	defines.NodeOut
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableIPv4EgressGateway {
		return out, nil
	}

	if dcfg.IdentityAllocationMode == option.IdentityAllocationModeKVstore {
		return out, errors.New("egress gateway is not supported in KV store identity allocation mode")
	}

	if dcfg.EnableHighScaleIPcache {
		return out, errors.New("egress gateway is not supported in high scale IPcache mode")
	}

	if !dcfg.MasqueradingEnabled() || !dcfg.EnableBPFMasquerade {
		return out, fmt.Errorf("egress gateway requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
	}

	if !dcfg.EnableRemoteNodeIdentity {
		// datapath code depends on remote node identities to distinguish between
		// cluster-local and cluster-egress traffic.
		return out, fmt.Errorf("egress gateway requires remote node identities (--%s=\"true\")", option.EnableRemoteNodeIdentity)
	}

	if dcfg.EnableL7Proxy {
		log.WithField(logfields.URL, "https://github.com/cilium/cilium/issues/19642").
			Warningf("both egress gateway and L7 proxy (--%s) are enabled. This is currently not fully supported: "+
				"if the same endpoint is selected both by an egress gateway and a L7 policy, endpoint traffic will not go through egress gateway.", option.EnableL7Proxy)
	}

	out.Manager, err = newEgressGatewayManager(p)
	if err != nil {
		return out, err
	}

	out.NodeDefines = map[string]string{
		"ENABLE_EGRESS_GATEWAY": "1",
	}

	return out, nil
}

func newEgressGatewayManager(p Params) (*Manager, error) {
	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	rateLimiter := workqueue.NewItemExponentialFailureRateLimiter(time.Millisecond*20, time.Minute*20)
	endpointEventRetryQueue := workqueue.NewRateLimitingQueueWithConfig(rateLimiter, workqueue.RateLimitingQueueConfig{})

	manager := &Manager{
		nodeDataStore:                 make(map[string]nodeTypes.Node),
		policyConfigs:                 make(map[policyID]*PolicyConfig),
		policyConfigsBySourceIP:       make(map[string][]*PolicyConfig),
		epDataStore:                   make(map[endpointID]*endpointMetadata),
		pendingEndpointEvents:         make(map[endpointID]*k8sTypes.CiliumEndpoint),
		endpointEventsQueue:           endpointEventRetryQueue,
		identityAllocator:             p.IdentityAllocator,
		installRoutes:                 p.Config.InstallEgressGatewayRoutes,
		reconciliationTriggerInterval: p.Config.EgressGatewayReconciliationTriggerInterval,
		policyMap:                     p.PolicyMap,
		policies:                      p.Policies,
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "egress_gateway_reconciliation",
		MinInterval: p.Config.EgressGatewayReconciliationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			reason := strings.Join(reasons, ", ")
			log.WithField(logfields.Reason, reason).Debug("reconciliation triggered")

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
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			if probes.HaveLargeInstructionLimit() != nil {
				return fmt.Errorf("egress gateway needs kernel 5.2 or newer")
			}

			go manager.processEvents(ctx, p.CacheStatus)
			manager.processCiliumEndpoints(ctx, &wg)
			return nil
		},
		OnStop: func(hc hive.HookContext) error {
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

// processEvents spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) processEvents(ctx context.Context, cacheStatus k8s.CacheStatus) {
	var globalSync, policySync bool
	maybeTriggerReconcile := func() {
		if !globalSync || !policySync {
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

	policyEvents := manager.policies.Events(ctx)
	for {
		select {
		case <-ctx.Done():
			return

		case <-cacheStatus:
			globalSync = true
			maybeTriggerReconcile()
			cacheStatus = nil

		case event := <-policyEvents:
			if event.Kind == resource.Sync {
				policySync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handlePolicyEvent(event)
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

// processCiliumEndpoints spawns a goroutine that:
//   - consumes the endpoint IDs returned by the endpointEventsQueue workqueue
//   - processes the CiliumEndpoints stored in pendingEndpointEvents for these
//     endpoint IDs
//   - in case the endpoint ID -> labels resolution fails, it adds back the
//     event to the workqueue so that it can be retried with an exponential
//     backoff
func (manager *Manager) processCiliumEndpoints(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)

	go func() {
		defer wg.Done()

		retryQueue := manager.endpointEventsQueue
		go func() {
			<-ctx.Done()
			retryQueue.ShutDown()
		}()

		for {
			item, shutdown := retryQueue.Get()
			if shutdown {
				break
			}
			endpointID := item.(types.NamespacedName)

			manager.pendingEndpointEventsLock.RLock()
			ep, ok := manager.pendingEndpointEvents[endpointID]
			manager.pendingEndpointEventsLock.RUnlock()

			var err error
			if ok {
				err = manager.addEndpoint(ep)
			} else {
				manager.deleteEndpoint(endpointID)
			}

			if err != nil {
				// if the endpoint event is still pending it means the manager
				// failed to resolve the endpoint ID to a set of labels, so add back
				// the item to the queue
				manager.endpointEventsQueue.AddRateLimited(endpointID)
			} else {
				// otherwise just remove it
				manager.endpointEventsQueue.Forget(endpointID)
			}

			manager.endpointEventsQueue.Done(endpointID)
		}
	}()
}

// Event handlers

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) onAddEgressPolicy(policy *Policy) error {
	config, err := ParseCEGP(policy)
	if err != nil {
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, config.id.Name)

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Debug("Added CiliumEgressGatewayPolicy")
	} else {
		logger.Debug("Updated CiliumEgressGatewayPolicy")
	}

	config.updateMatchedEndpointIDs(manager.epDataStore)

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

	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete CiliumEgressGatewayPolicy: policy not found")
	}

	logger.Debug("Deleted CiliumEgressGatewayPolicy")

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

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
	})

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.WithError(err).
			Warning("Failed to get identity labels for endpoint")
		return err
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return nil
	}

	if _, ok := manager.epDataStore[epData.id]; ok {
		logger.Debug("Updated CiliumEndpoint")
	} else {
		logger.Debug("Added CiliumEndpoint")
	}

	manager.epDataStore[epData.id] = epData

	manager.setEventBitmap(eventUpdateEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint updated")

	return nil
}

func (manager *Manager) deleteEndpoint(id types.NamespacedName) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: id.Name,
		logfields.K8sNamespace:    id.Namespace,
	})

	logger.Debug("Deleted CiliumEndpoint")
	delete(manager.epDataStore, id)

	manager.setEventBitmap(eventDeleteEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint deleted")
}

// OnUpdateEndpoint is the event handler for endpoint additions and updates.
func (manager *Manager) OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	manager.pendingEndpointEventsLock.Lock()
	manager.pendingEndpointEvents[id] = endpoint
	manager.pendingEndpointEventsLock.Unlock()

	manager.endpointEventsQueue.Add(id)
}

// OnDeleteEndpoint is the event handler for endpoint deletions.
func (manager *Manager) OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	manager.pendingEndpointEventsLock.Lock()
	delete(manager.pendingEndpointEvents, id)
	manager.pendingEndpointEventsLock.Unlock()

	manager.endpointEventsQueue.Add(id)
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

	reason := ""
	if e == eventUpdateNode {
		reason = "node updated"
	} else if e == eventDeleteNode {
		reason = "node deleted"
	}

	manager.setEventBitmap(e)
	manager.reconciliationTrigger.TriggerWithReason(reason)
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

	if !manager.installRoutes {
		return
	}

	// We can only have one default route per interface. Warn if there are
	// conflicts on the desired egress IP per interface.
	policyByInterfaceIndex := make(map[int]*PolicyConfig)
	for _, policyConfig := range manager.policyConfigs {
		gwc := policyConfig.gatewayConfig

		if !gwc.localNodeConfiguredAsGateway {
			continue
		}

		currentPolicy := policyByInterfaceIndex[gwc.ifaceIndex]
		if currentPolicy == nil {
			policyByInterfaceIndex[gwc.ifaceIndex] = policyConfig
			continue
		}

		currentEgressIP := currentPolicy.gatewayConfig.egressIP
		if gwc.egressIP.IP.Equal(currentEgressIP.IP) && bytes.Equal(gwc.egressIP.Mask, currentEgressIP.Mask) {
			continue
		}

		log.WithFields(logrus.Fields{
			logfields.CiliumEgressGatewayPolicyName: policyConfig.id,
			logfields.Interface:                     policyConfig.policyGwConfig.iface,
			logfields.EgressIP:                      policyConfig.policyGwConfig.egressIP,
		}).Errorf("Conflict with policy %s: Selects the same egress interface but uses a different egress IP (%s).", currentPolicy.id, currentEgressIP.String())
	}
}

func (manager *Manager) addMissingIpRulesAndRoutes(isRetry bool) (shouldRetry bool) {
	if !manager.installRoutes {
		return false
	}

	for _, policyConfig := range manager.policyConfigs {
		gwc := &policyConfig.gatewayConfig

		if !gwc.localNodeConfiguredAsGateway || len(policyConfig.matchedEndpoints) == 0 {
			continue
		}

		logger := log.WithFields(logrus.Fields{
			logfields.EgressIP:  gwc.egressIP.IP,
			logfields.LinkIndex: gwc.ifaceIndex,
		})

		if err := addEgressIpRoutes(gwc); err != nil {
			logger.WithError(err).Warn("Can't add IP routes")
		} else {
			logger.Debug("Added IP routes")
		}

		routingTableIdx := egressGatewayRoutingTableIdx(gwc.ifaceIndex)

		ipRules, err := listEgressIpRulesForRoutingTable(routingTableIdx)
		if err != nil {
			logger.WithError(err).Warn("Can't fetch IP rules")
			continue
		}

		addIPRulesForConfig := func(endpointIP net.IP, dstCIDR *net.IPNet, gwc *gatewayConfig) {
			logger := log.WithFields(logrus.Fields{
				logfields.SourceIP:        endpointIP,
				logfields.DestinationCIDR: dstCIDR.String(),
				logfields.EgressIP:        gwc.egressIP.IP,
				logfields.LinkIndex:       gwc.ifaceIndex,
			})

			// check if the corresponding IP rule already exists
			for _, ipRule := range ipRules {
				if egressIPRuleMatches(&ipRule, endpointIP, dstCIDR) {
					return
				}
			}

			// insert the missing rule
			newRule := newEgressIpRule(endpointIP, dstCIDR, routingTableIdx)

			if err := netlink.RuleAdd(newRule); err != nil {
				if isRetry {
					logger.WithError(err).Warn("Can't add IP rule")
				} else {
					logger.WithError(err).Debug("Can't add IP rule, will retry")
					shouldRetry = true
				}
			} else {
				logger.Debug("Added IP rule")
			}
		}

		policyConfig.forEachEndpointAndDestination(addIPRulesForConfig)
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

			if ipRule.Table != egressGatewayRoutingTableIdx(gwc.ifaceIndex) {
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

	// Build a list of all the network interfaces that are being actively used by egress gateway,
	// and by which policy they are selected.
	activeEgressGwIfaceIndexes := make(map[int]*PolicyConfig)
	for _, policyConfig := range manager.policyConfigs {
		gwc := &policyConfig.gatewayConfig

		if !gwc.localNodeConfiguredAsGateway {
			continue
		}

		// check if the policy selects at least one endpoint
		if len(policyConfig.matchedEndpoints) == 0 {
			continue
		}

		activeEgressGwIfaceIndexes[gwc.ifaceIndex] = policyConfig
	}

	// Fetch all IP routes, and delete the unused EgressGW-specific routes:
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Table: unix.RT_TABLE_UNSPEC,
	}, netlink.RT_FILTER_TABLE)

	if err != nil {
		logger.WithError(err).Error("Cannot list IP routes")
		return
	}

	for _, route := range routes {
		linkIndex := route.LinkIndex

		// Keep the route if it was not created by EgressGW.
		if route.Table != egressGatewayRoutingTableIdx(linkIndex) {
			continue
		}

		policyConfig := activeEgressGwIfaceIndexes[linkIndex]

		// Keep the route if it still matches the policy on this interface.
		if policyConfig != nil {
			/* Only take a closer look at next-hop routes for now: */
			if route.Scope != netlink.SCOPE_LINK {
				continue
			}

			eniGatewayIP := getFirstIPInHostRange(policyConfig.gatewayConfig.egressIP)
			routeMaskSize, routeMaskTotal := route.Dst.Mask.Size()

			if route.Dst.IP.Equal(eniGatewayIP) &&
				routeMaskSize == 32 && routeMaskTotal == 32 {
				continue
			}
		}

		deleteIpRoute(route)
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
	case manager.eventBitmapIsSet(eventUpdateEndpoint, eventDeleteEndpoint, eventK8sSyncDone):
		manager.updatePoliciesMatchedEndpointIDs()
		fallthrough
	case manager.eventBitmapIsSet(eventAddPolicy, eventDeletePolicy):
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

	// clear the events bitmap
	manager.eventsBitmap = 0
}

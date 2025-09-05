// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vteppolicy

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/vtep_policy"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"vteppolicy",
	"Vtep Policy allows to use external VTEPs access pods",
	cell.Config(defaultConfig),
	cell.Provide(NewVtepPolicyManager),
	cell.Provide(newPolicyResource),
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
	// Default amount of time between triggers of vtep policy state
	// reconciliations are invoked
	VtepPolicyReconciliationTriggerInterval time.Duration
}

var defaultConfig = Config{
	VtepPolicyReconciliationTriggerInterval: 1 * time.Second,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("vtep-policy-reconciliation-trigger-interval", def.VtepPolicyReconciliationTriggerInterval, "Time between triggers of vtep policy state reconciliations")
}

// The vtep policy manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// vteppolicy bpf policy map accordingly.
type Manager struct {
	logger *slog.Logger

	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

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

	// reconciliationTriggerInterval is the amount of time between triggers
	// of reconciliations are invoked
	reconciliationTriggerInterval time.Duration

	// eventsBitmap is a bitmap that tracks which type of events has been
	// received by the manager (e.g. node added or policy removed) since the
	// last invocation of the reconciliation logic
	eventsBitmap eventType

	// reconciliationTrigger is the trigger used to reconcile the state of
	// the node with the desired vtep policy state.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger

	// reconciliationEventsCount keeps track of how many reconciliation
	// events have occoured
	reconciliationEventsCount atomic.Uint64

	// policyMap4 communicates the active IPv4 policies to the datapath.
	policyMap *vtep_policy.VtepPolicyMap
}

type Params struct {
	cell.In

	Logger *slog.Logger

	Config            Config
	DaemonConfig      *option.DaemonConfig
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap         *vtep_policy.VtepPolicyMap
	Policies          resource.Resource[*Policy]
	Nodes             resource.Resource[*cilium_api_v2.CiliumNode]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]

	Lifecycle cell.Lifecycle
}

func NewVtepPolicyManager(p Params) (out struct {
	cell.Out

	*Manager
	defines.NodeOut
	tunnel.EnablerOut
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableVTEP {
		return out, fmt.Errorf("vtep policy requires --%s=\"true\" ", option.EnableVTEP)
	}

	out.Manager, err = newVtepPolicyManager(p)
	if err != nil {
		return out, err
	}

	out.EnablerOut = tunnel.NewEnabler(true)

	return out, nil
}

func newVtepPolicyManager(p Params) (*Manager, error) {
	manager := &Manager{
		logger:                        p.Logger,
		policyConfigs:                 make(map[policyID]*PolicyConfig),
		epDataStore:                   make(map[endpointID]*endpointMetadata),
		identityAllocator:             p.IdentityAllocator,
		reconciliationTriggerInterval: p.Config.VtepPolicyReconciliationTriggerInterval,
		policies:                      p.Policies,
		policyMap:                     p.PolicyMap,
		ciliumNodes:                   p.Nodes,
		endpoints:                     p.Endpoints,
		nodesAddresses2Labels:         make(map[string]map[string]string),
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "vtep_policy_reconciliation",
		MinInterval: p.Config.VtepPolicyReconciliationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			reason := strings.Join(reasons, ", ")
			manager.logger.Debug("reconciliation triggered", logfields.Reason, reason)

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
		err := manager.onAddVtepPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		manager.onDeleteVtepPolicy(event.Object)
		event.Done(nil)
	}
}

// Event handlers

// onAddVtepPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) onAddVtepPolicy(policy *Policy) error {
	logger := manager.logger.With(logfields.CiliumVtepPolicyName, policy.Name)

	config, err := ParseCVP(policy)
	if err != nil {
		logger.Warn("Failed to parse CiliumVtepPolicy", logfields.Error, err)
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Debug("Added CiliumVtepPolicy")
	} else {
		logger.Debug("Updated CiliumVtepPolicy")
	}

	config.updateMatchedEndpointIDs(manager.epDataStore)

	manager.policyConfigs[config.id] = config

	manager.setEventBitmap(eventAddPolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy added")
	return nil
}

// onDeleteVtepPolicy deletes the internal state associated with the given
// policy, including vteppolicy eBPF map entries.
func (manager *Manager) onDeleteVtepPolicy(policy *Policy) {
	configID := ParseCVPConfigID(policy)

	manager.Lock()
	defer manager.Unlock()

	logger := manager.logger.With(logfields.CiliumVtepPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		manager.logger.Warn("Can't delete CiliumVtepPolicy: policy not found")
	}

	logger.Debug("Deleted CiliumVtepPolicy")

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
		logger.Warn("Endpoint is missing identity metadata, skipping update to vtep policy.")
		return nil
	}

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.Warn("Failed to get identity labels for endpoint", logfields.Error, err)
		return err
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.Error("Failed to get valid endpoint metadata, skipping update to vtep policy.", logfields.Error, err)
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

func (manager *Manager) deleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.Lock()
	defer manager.Unlock()

	logger := manager.logger.With(
		logfields.K8sEndpointName, endpoint.Name,
		logfields.K8sNamespace, endpoint.Namespace,
		logfields.K8sUID, endpoint.UID,
	)

	logger.Debug("Deleted CiliumEndpoint")
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
	manager.setEventBitmap(eventUpdateNode)
	manager.reconciliationTrigger.TriggerWithReason("node updated")
}

func (manager *Manager) updatePoliciesMatchedEndpointIDs() {
	for _, policy := range manager.policyConfigs {
		policy.updateMatchedEndpointIDs(manager.epDataStore)
	}
}

func (manager *Manager) updateVtepRules() {
	if manager.policyMap == nil {
		manager.logger.Error("policyMap is nil")
		return
	}

	vtepPolicies := map[vtep_policy.VtepPolicyKey]vtep_policy.VtepPolicyVal{}
	manager.policyMap.IterateWithCallback(
		func(key *vtep_policy.VtepPolicyKey, val *vtep_policy.VtepPolicyVal) {
			vtepPolicies[*key] = *val
		})

	// Start with the assumption that all the entries currently present in the
	// BPF map are stale. Then as we walk the entries below and discover which
	// entries are actually still needed, shrink this set down.
	stale := sets.KeySet(vtepPolicies)

	addVtepRule := func(endpointIP net.IP, dstCIDR *cidr.CIDR, vtep *vtepConfig) {
		if endpointIP.To4() == nil {
			return
		}

		if dstCIDR.IP.To4() == nil {
			return
		}

		if vtep == nil {
			return
		}

		policyKey := vtep_policy.NewKey(endpointIP, dstCIDR)
		// This key needs to be present in the BPF map, hence remove it from
		// the list of stale ones.
		stale.Delete(policyKey)

		logger := manager.logger.With(
			logfields.SourceIP, endpointIP,
			logfields.DestinationCIDR, dstCIDR.String(),
			logfields.VtepIP, vtep.vtepIP,
			logfields.Rmac, vtep.rmac,
		)

		if err := manager.policyMap.UpdateVtepPolicyMapping(endpointIP, dstCIDR, vtep.vtepIP, vtep.rmac); err != nil {
			logger.Error("Error applying vtep policy", logfields.Error, err)
		} else {
			logger.Debug("vtep policy applied")
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndCIDR(addVtepRule)
	}

	// Remove all the entries marked as stale.
	for policyKey := range stale {
		logger := manager.logger.With(
			logfields.SourceIP, policyKey.SourceIP,
			logfields.DestinationCIDR, policyKey.DestCIDR.String(),
		)

		if err := manager.policyMap.Delete(&policyKey); err != nil {
			logger.Error("Error removing vtep gateway policy", logfields.Error, err)
		} else {
			logger.Debug("Vtep gateway policy removed")
		}
	}
}

// reconcileLocked is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (vtep policy map entries).
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

	// Update the content of the BPF maps.
	manager.updateVtepRules()

	// clear the events bitmap
	manager.eventsBitmap = 0

	manager.reconciliationEventsCount.Add(1)
}

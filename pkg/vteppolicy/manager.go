// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vteppolicy

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/vtep_policy"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"vteppolicy",
	"Vtep Policy allows to use external VTEPs access pods",
	cell.Config(defaultConfig),
	cell.Provide(NewVtepPolicyManager),
	cell.Provide(newPolicyResource),
	cell.Provide(func(dcfg *option.DaemonConfig) tunnel.EnablerOut {
		if !dcfg.EnableVTEP {
			return tunnel.EnablerOut{}
		}
		return tunnel.NewEnabler(true)
	}),
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
	logger            *slog.Logger
	reconcileInterval time.Duration
	// reconciliationEventsCount keeps track of how many reconciliation
	// events have occoured
	reconciliationEventsCount atomic.Uint64

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// endpoints allows reading endpoint CRD from k8s.
	endpoints resource.Resource[*k8sTypes.CiliumEndpoint]

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// policyMap4 communicates the active IPv4 policies to the datapath.
	policyMap *vtep_policy.VtepPolicyMap

	// chEndpoint is used to trigger reconciliation for endpoint changes.
	chEndpoint chan *endpointMetadata

	// chPolicy is used to trigger reconciliation for policy changes.
	chPolicy chan *PolicyConfig
}

// reconcile waits for the policy and endpoint resources to be synced, and then runs the reconciliation
// for each policy or endpoint change.
// It reconciles the desired state by updating the internal cache for policies and endpoints.
// It tries to reconcile the desired state by updating the vteppolicy bpf map entries.
func (manager *Manager) reconcile(ctx context.Context) {
	var policySync, endpointSync bool

	/*TODO(informalict):
	- support for p.Config.VtepPolicyReconciliationTriggerInterval
	- logs for reconciliation events
	*/

	for {
		select {
		case <-ctx.Done():
			return
		case endpoint := <-manager.chEndpoint:
			if endpoint.EventKind == resource.Sync {
				endpointSync = true
				continue
			}
			if endpoint.EventKind == resource.Upsert {
				manager.epDataStore[endpoint.id] = endpoint
			} else {
				delete(manager.epDataStore, endpoint.id)
			}
		case policy := <-manager.chPolicy:
			if policy.EventKind == resource.Sync {
				policySync = true
				continue
			}

			if policy.EventKind == resource.Upsert {
				policy.updateMatchedEndpointIDs(manager.epDataStore)
				manager.policyConfigs[policy.id] = policy
			} else {
				if manager.policyConfigs[policy.id] != nil {
					delete(manager.policyConfigs, policy.id)
				} else {
					manager.logger.Warn("Can't delete CiliumVtepPolicy: policy not found")
				}
			}
		}

		if policySync && endpointSync {
			manager.reconcileState()
		}
	}
}

type Params struct {
	cell.In

	Logger *slog.Logger

	Config            Config
	DaemonConfig      *option.DaemonConfig
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap         *vtep_policy.VtepPolicyMap
	Policies          resource.Resource[*Policy]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]

	Lifecycle cell.Lifecycle
}

func NewVtepPolicyManager(p Params) (out struct {
	cell.Out

	*Manager
	defines.NodeOut
}, err error) {
	dcfg := p.DaemonConfig
	out.Manager = nil

	if !dcfg.EnableVTEP {
		return out, fmt.Errorf("vtep policy requires --%s=\"true\" ", option.EnableVTEP)
	}

	out.Manager, err = newVtepPolicyManager(p)
	if err != nil {
		return out, err
	}

	return out, nil
}

func newVtepPolicyManager(p Params) (*Manager, error) {
	manager := &Manager{
		logger:            p.Logger,
		policyConfigs:     make(map[policyID]*PolicyConfig),
		epDataStore:       make(map[endpointID]*endpointMetadata),
		identityAllocator: p.IdentityAllocator,
		policies:          p.Policies,
		policyMap:         p.PolicyMap,
		endpoints:         p.Endpoints,
		chEndpoint:        make(chan *endpointMetadata),
		chPolicy:          make(chan *PolicyConfig),
	}

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			wg.Go(func() {
				manager.processEvents(ctx)
			})

			wg.Go(func() {
				manager.reconcile(ctx)
			})
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
	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	endpointsRateLimit := workqueue.NewTypedItemExponentialFailureRateLimiter[resource.WorkItem](
		time.Millisecond*20,
		time.Minute*20,
	)

	policyEvents := manager.policies.Events(ctx)
	endpointEvents := manager.endpoints.Events(ctx, resource.WithRateLimiter(endpointsRateLimit))

	for {
		select {
		case <-ctx.Done():
			return

		case event := <-policyEvents:
			manager.handlePolicyEvent(event)
		case event := <-endpointEvents:
			manager.handleEndpointEvent(event)
		}
	}
}

func (manager *Manager) handlePolicyEvent(event resource.Event[*Policy]) {
	var err error

	switch event.Kind {
	case resource.Sync:
		manager.chPolicy <- &PolicyConfig{EventKind: resource.Sync}
	case resource.Upsert:
		err = manager.onAddVtepPolicy(event.Object)
	case resource.Delete:
		manager.onDeleteVtepPolicy(event.Object)
	}

	event.Done(err)
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

	manager.chPolicy <- config

	return nil
}

// onDeleteVtepPolicy deletes the internal state associated with the given
// policy, including vteppolicy eBPF map entries.
func (manager *Manager) onDeleteVtepPolicy(policy *Policy) {
	configID := ParseCVPConfigID(policy)

	logger := manager.logger.With(logfields.CiliumVtepPolicyName, configID.Name)

	manager.chPolicy <- &PolicyConfig{id: configID, EventKind: resource.Delete}

	logger.Debug("Deleted CiliumVtepPolicy")
}

func (manager *Manager) addEndpoint(endpoint *k8sTypes.CiliumEndpoint) error {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

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

	epData.EventKind = resource.Upsert
	manager.chEndpoint <- epData

	logger.Debug("CiliumEndpoint accepted for adding/updating")

	return nil
}

func (manager *Manager) deleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	logger := manager.logger.With(
		logfields.K8sEndpointName, endpoint.Name,
		logfields.K8sNamespace, endpoint.Namespace,
		logfields.K8sUID, endpoint.UID,
	)

	manager.chEndpoint <- &endpointMetadata{
		id:        endpoint.UID,
		EventKind: resource.Delete,
	}

	logger.Debug("CiliumEndpoint accepted for deletion")
}

func (manager *Manager) handleEndpointEvent(event resource.Event[*k8sTypes.CiliumEndpoint]) {
	endpoint := event.Object
	var err error

	switch event.Kind {
	case resource.Sync:
		manager.chEndpoint <- &endpointMetadata{EventKind: resource.Sync}
	case resource.Upsert:
		err = manager.addEndpoint(endpoint)
	default:
		manager.deleteEndpoint(endpoint)
	}

	event.Done(err)
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

	addVtepRule := func(endpointIP netip.Addr, dstCIDR netip.Prefix, vtep *vtepConfig) {
		if !endpointIP.Is4() {
			return
		}

		if !dstCIDR.Addr().Is4() {
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
			logfields.VtepMAC, vtep.vtepMAC,
		)

		if err := manager.policyMap.UpdateVtepPolicyMapping(endpointIP, dstCIDR, vtep.vtepIP, vtep.vtepMAC); err != nil {
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

// reconcileState is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (vtep policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcileState() {
	manager.updatePoliciesMatchedEndpointIDs()

	// Update the content of the BPF maps.
	manager.updateVtepRules()

	manager.reconciliationEventsCount.Add(1)
}

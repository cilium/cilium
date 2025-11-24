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
	logger *slog.Logger
	// reconciliationEventsCount keeps track of how many reconciliation events have occurred.
	reconciliationEventsCount atomic.Uint64

	// policies allow reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// endpoints allow reading endpoint CRD from k8s.
	endpoints resource.Resource[*k8sTypes.CiliumEndpoint]

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// policyMap4 communicates the active IPv4 policies to the datapath.
	policyMap *vtep_policy.VtepPolicyMap

	// chEndpoint is used to trigger reconciliation for endpoint changes.
	chEndpoint chan endpointMetadataEvent

	// chPolicy is used to trigger reconciliation for policy changes.
	chPolicy chan policyConfigEvent
}

// reconcile waits for the policy and endpoint resources to be synced, and then runs the reconciliation
// for each policy or endpoint change.
// It reconciles the desired state by updating the internal cache for policies and endpoints.
// It tries to reconcile the desired state by updating the vteppolicy bpf map entries.
func (manager *Manager) reconcile(ctx context.Context, minInterval time.Duration) {
	var policySync, endpointSync bool
	// epDataStore stores desired endpointId to endpoint metadata mapping.
	epDataStore := make(map[endpointID]*endpointMetadata)
	// policyConfigs stores desired policy configs indexed by policyID.
	policyConfigs := make(map[policyID]*PolicyConfig)

	/*TODO(informalict):
	- logs for reconciliation events
	*/
	minDur := NewMinDuration(minInterval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-minDur.GetChannel():
			// For nil channel it will never be fired.
		case endpointEvent := <-manager.chEndpoint:
			if endpointEvent.EventKind == resource.Sync {
				endpointSync = true
			} else if endpointEvent.EventKind == resource.Upsert {
				epDataStore[endpointEvent.id] = endpointEvent.endpointMetadata
			} else {
				delete(epDataStore, endpointEvent.id)
			}
		case policyEvent := <-manager.chPolicy:
			if policyEvent.EventKind == resource.Sync {
				policySync = true
			} else if policyEvent.EventKind == resource.Upsert {
				policyEvent.PolicyConfig.updateMatchedEndpointIDs(epDataStore) // TODO(informalict): it is launched below for all policies.
				policyConfigs[policyEvent.PolicyConfig.id] = policyEvent.PolicyConfig
			} else {
				if policyConfigs[policyEvent.PolicyConfig.id] != nil {
					delete(policyConfigs, policyEvent.PolicyConfig.id)
				} else {
					manager.logger.Warn("Can't delete CiliumVtepPolicy: policy not found")
				}
			}
		}

		if !policySync || !endpointSync {
			// Wait until the required resources are synced.
			continue
		}

		if !minDur.Check() {
			// Go to the above loop and wait until the required duration has passed.
			// When it waits for the required duration, it can be woken up by the policy or endpoint channel.
			// Thanks to this approach, it is possible to collect more events (without blocking channels), or
			// react on cancellation of the context.
			continue
		}

		// From here on, reconciliation starts.

		// TODO(informalict):
		// - here we could launch the below logic in separate goroutines, if we copied policyConfigs and epDataStore.
		//   Thanks to that the above `select` could apply new changes in the meantime, so event's listener will not hang.
		// - The below loop could be avoided, if policyConfigs are inlined
		// with epDataStore (so when epDataStore changes, or policy is updated).

		// Apply endpoints to cached policies.
		for _, policy := range policyConfigs {
			policy.updateMatchedEndpointIDs(epDataStore)
		}

		manager.updateVtepRules(policyConfigs)

		minDur.SetLastCheck()
		// TODO(informalict) do we want to add error counter in case the above function fails?
		manager.reconciliationEventsCount.Add(1)
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
		identityAllocator: p.IdentityAllocator,
		policies:          p.Policies,
		policyMap:         p.PolicyMap,
		endpoints:         p.Endpoints,
		chEndpoint:        make(chan endpointMetadataEvent),
		chPolicy:          make(chan policyConfigEvent),
	}

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			wg.Go(func() {
				manager.processEvents(ctx)
			})

			wg.Go(func() {
				manager.reconcile(ctx, p.Config.VtepPolicyReconciliationTriggerInterval)
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
		manager.chPolicy <- policyConfigEvent{EventKind: resource.Sync}
	case resource.Upsert:
		err = manager.onAddVtepPolicy(event.Object)
	case resource.Delete:
		manager.onDeleteVtepPolicy(event.Object)
	}

	event.Done(err)
}

// Event handlers

// onAddVtepPolicy parses the given policy config and populates it to a policy channel.
func (manager *Manager) onAddVtepPolicy(policy *Policy) error {
	logger := manager.logger.With(logfields.CiliumVtepPolicyName, policy.Name)

	config, err := ParseCVP(policy)
	if err != nil {
		logger.Warn("Failed to parse CiliumVtepPolicy", logfields.Error, err)
		return err
	}

	logger.Debug("CiliumVtepPolicy accepted for adding/updating")
	manager.chPolicy <- policyConfigEvent{PolicyConfig: config, EventKind: resource.Upsert}

	return nil
}

// onDeleteVtepPolicy populates event to a policy channel.
func (manager *Manager) onDeleteVtepPolicy(policy *Policy) {
	configID := ParseCVPConfigID(policy)

	logger := manager.logger.With(logfields.CiliumVtepPolicyName, configID.Name)
	logger.Debug("CiliumVtepPolicy accepted for deletion")

	manager.chPolicy <- policyConfigEvent{
		PolicyConfig: &PolicyConfig{
			id: configID,
		},
		EventKind: resource.Delete,
	}
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

	logger.Debug("CiliumEndpoint accepted for adding/updating")
	manager.chEndpoint <- endpointMetadataEvent{endpointMetadata: epData, EventKind: resource.Upsert}

	return nil
}

func (manager *Manager) deleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	logger := manager.logger.With(
		logfields.K8sEndpointName, endpoint.Name,
		logfields.K8sNamespace, endpoint.Namespace,
		logfields.K8sUID, endpoint.UID,
	)

	manager.chEndpoint <- endpointMetadataEvent{
		endpointMetadata: &endpointMetadata{
			id: endpoint.UID,
		},
		EventKind: resource.Delete,
	}

	logger.Debug("CiliumEndpoint accepted for deletion")
}

func (manager *Manager) handleEndpointEvent(event resource.Event[*k8sTypes.CiliumEndpoint]) {
	endpoint := event.Object
	var err error

	switch event.Kind {
	case resource.Sync:
		manager.chEndpoint <- endpointMetadataEvent{EventKind: resource.Sync}
	case resource.Upsert:
		err = manager.addEndpoint(endpoint)
	default:
		manager.deleteEndpoint(endpoint)
	}

	event.Done(err)
}

// updateVtepRules updates the content of the BPF maps.
// Whenever an error occurs, it will just log it and move to the next item,
// in order to reconcile as many states as possible.
func (manager *Manager) updateVtepRules(policyConfigs map[policyID]*PolicyConfig) {
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

	for _, policyConfig := range policyConfigs {
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

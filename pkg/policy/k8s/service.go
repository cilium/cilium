// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"

	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/util/sets"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// Cilium network policy can refer to Kubernetes services via 'ToServices'.
// The service and backend information is available in the agent via the
// Table[*loadbalancer.Service] and Table[*loadbalancer.Backend] StateDB
// tables. On changes to these tables we'll need to recompute rules of
// CNPs that refer to them conversily we need to query the tables for matches
// when CNP is added or changed.
//
// To keep things fairly simple this is implemented constructing a stream
// of service changes (including associated backend changes) that is used
// to trigger the recomputation of a rule.

// serviceEvent captures the relevant description of a change to a service.
// This is used to find matching CNPs and trigger recomputation if needed.
type serviceEvent struct {
	deleted          bool
	name             loadbalancer.ServiceName
	labels           labels.Labels
	selector         map[string]string
	backendRevisions []statedb.Revision
	previous         *serviceEvent
}

func (s serviceEvent) Equal(other serviceEvent) bool {
	return s.deleted == other.deleted &&
		s.name.Equal(other.name) &&
		s.labels.Equals(other.labels) &&
		slices.Equal(s.backendRevisions, other.backendRevisions) &&
		maps.Equal(s.selector, other.selector)
}

func (s serviceEvent) getLabels() labels.Labels { return s.labels }
func (s serviceEvent) getName() string          { return s.name.Name() }
func (s serviceEvent) getNamespace() string     { return s.name.Namespace() }

var _ serviceDetailer = serviceEvent{}

// serviceEventStream constructs stream of [serviceEvent]. An event is only emitted if it differs from a previous event
// emitted for the same service name.
func serviceEventStream(db *statedb.DB, services statedb.Table[*loadbalancer.Service], backends statedb.Table[*loadbalancer.Backend]) stream.Observable[serviceEvent] {
	return stream.FuncObservable[serviceEvent](func(ctx context.Context, emit func(serviceEvent), complete func(error)) {
		go func() {
			limiter := rate.NewLimiter(50*time.Millisecond, 1)
			defer limiter.Stop()

			previousEvents := map[loadbalancer.ServiceName]serviceEvent{}

			wtxn := db.WriteTxn(services, backends)
			defer wtxn.Abort()
			serviceChanges, err := services.Changes(wtxn)
			if err != nil {
				complete(err)
				return
			}
			backendChanges, err := backends.Changes(wtxn)
			if err != nil {
				complete(err)
				return
			}
			wtxn.Commit()
			defer complete(nil)

			for {
				txn := db.ReadTxn()

				// Collect the names of all changed services. Both a change to a service or to the
				// set of backends associated with a service is worthy of a notification.
				changed := sets.Set[loadbalancer.ServiceName]{}

				servicesIter, watchServices := serviceChanges.Next(txn)
				for ev := range servicesIter {
					changed.Insert(ev.Object.Name)
				}

				backendsIter, watchBackends := backendChanges.Next(txn)
				for ev := range backendsIter {
					be := ev.Object
					for inst := range be.Instances.All() {
						changed.Insert(inst.ServiceName)
					}
				}

				// For each changed service look it up along with the associated backends and
				// emit a notification for it.
				for name := range changed {
					// Look up the service and the previous notification we sent for it.
					prevEvent, prevFound := previousEvents[name]
					svc, _, found := services.Get(txn, loadbalancer.ServiceByName(name))

					// If no previously sent notification is found then no need to emit anything
					// for the deletion.
					if !found && !prevFound {
						continue
					}

					var newEvent serviceEvent
					if found {
						newEvent.name = svc.Name
						newEvent.labels = svc.Labels
						newEvent.selector = svc.Selector
						for _, rev := range backends.List(txn, loadbalancer.BackendByServiceName(name)) {
							newEvent.backendRevisions = append(newEvent.backendRevisions, rev)
						}
						if prevFound {
							prevEvent.previous = nil
							newEvent.previous = &prevEvent
						}
						previousEvents[name] = newEvent
					} else {
						newEvent = prevEvent
						newEvent.deleted = true
						delete(previousEvents, name)
					}

					if prevFound && newEvent.Equal(prevEvent) {
						// Nothing relevant changed, skip.
						continue
					}

					emit(newEvent)
				}

				select {
				case <-watchServices:
				case <-watchBackends:
				case <-ctx.Done():
					return
				}
				if limiter.Wait(ctx) != nil {
					return
				}
			}
		}()
	})
}

// onServiceEvent processes a ServiceNotification and (if necessary)
// recalculates all policies affected by this change.
func (p *policyWatcher) onServiceEvent(event serviceEvent) {
	err := p.updateToServicesPolicies(event)
	if err != nil {
		p.log.Warn(
			"Failed to recalculate CiliumNetworkPolicy rules after service event",
			logfields.Error, err,
			logfields.Event, event,
		)
	}
}

// updateToServicesPolicies is to be invoked when a service has changed (i.e. it was
// added, removed, its endpoints have changed, or its labels have changed).
// This function then checks if any of the known CNP/CCNPs are affected by this
// change, and recomputes them by calling resolveCiliumNetworkPolicyRefs.
func (p *policyWatcher) updateToServicesPolicies(ev serviceEvent) error {
	var errs []error

	// candidatePolicyKeys contains the set of policy names we need to process
	// for this service update. By default, we consider all policies with
	// a ToServices selector as candidates.
	candidatePolicyKeys := p.toServicesPolicies

	if ev.previous != nil && ev.labels.Equals(ev.previous.labels) {
		// If the service definition itself has not changed, and it's not the
		// first time we process this service, we only need to check the
		// policies which are known to select the old version of the service
		candidatePolicyKeys = p.cnpByServiceID[ev.name]
	}

	// Iterate over all policies potentially affected by this service update,
	// and re-resolve the policy refs for each.
	for key := range candidatePolicyKeys {
		cnp, ok := p.cnpCache[key]
		if !ok {
			p.log.Error(
				"BUG: Candidate policy for service update not found. Please report this bug to Cilium developers.",
				logfields.Key, key,
				logfields.ServiceID, ev.name,
			)
			continue
		}

		// Skip policies which are not affected by this service update
		if !(p.cnpMatchesService(cnp, ev) ||
			(ev.previous != nil && p.cnpMatchesService(cnp, *ev.previous))) {
			continue
		}

		if p.config.Debug {
			p.log.Debug(
				"Service updated or deleted, recalculating CiliumNetworkPolicy rules",
				logfields.CiliumNetworkPolicyName, cnp.Name,
				logfields.K8sAPIVersion, cnp.APIVersion,
				logfields.K8sNamespace, cnp.Namespace,
				logfields.ServiceID, ev.name,
			)
		}
		initialRecvTime := time.Now()

		resourceID := resourceIDForCiliumNetworkPolicy(key, cnp)

		errs = append(errs, p.resolveCiliumNetworkPolicyRefs(cnp, key, initialRecvTime, resourceID, nil))
	}
	return errors.Join(errs...)
}

// resolveToServices translates all ToServices rules found in the provided CNP
// and to corresponding ToCIDRSet rules. Mutates the passed in cnp in place.
func (p *policyWatcher) resolveToServices(key resource.Key, cnp *types.SlimCNP) {
	txn := p.db.ReadTxn()

	for svc := range p.services.All(txn) {
		svcEndpoints := newServiceEndpoints(svc, txn, p.backends)

		// This extracts the selected service endpoints from the rule
		// and translates it to a ToCIDRSet/ToEndpoints
		numMatches := svcEndpoints.processRule(cnp.Spec)
		for _, spec := range cnp.Specs {
			numMatches += svcEndpoints.processRule(spec)
		}

		// Mark the policy as selecting the service svcID. This allows us to
		// reduce the number of policy candidates in updateToServicesPolicies
		if numMatches > 0 {
			p.markCNPForService(key, svc.Name)
		} else {
			p.clearCNPForService(key, svc.Name)
		}
	}
}

type backendPrefixes = []api.CIDR

// cnpMatchesService returns true if the cnp contains a ToServices rule which
// matches the provided service svcID/svc
func (p *policyWatcher) cnpMatchesService(cnp *types.SlimCNP, ev serviceEvent) bool {
	if hasMatchingToServices(cnp.Spec, ev) {
		return true
	}

	for _, spec := range cnp.Specs {
		if hasMatchingToServices(spec, ev) {
			return true
		}
	}

	return false
}

// markCNPForService marks that a policy (referred to by 'key') contains a
// ToServices selector selecting the service svcID
func (p *policyWatcher) markCNPForService(key resource.Key, svcID loadbalancer.ServiceName) {
	svcMap, ok := p.cnpByServiceID[svcID]
	if !ok {
		svcMap = make(map[resource.Key]struct{}, 1)
		p.cnpByServiceID[svcID] = svcMap
	}

	svcMap[key] = struct{}{}
}

// clearCNPForService indicates that a policy (referred to by 'key') no longer
// selects the service svcID via a ToServices rule
func (p *policyWatcher) clearCNPForService(key resource.Key, svcID loadbalancer.ServiceName) {
	delete(p.cnpByServiceID[svcID], key)
	if len(p.cnpByServiceID[svcID]) == 0 {
		delete(p.cnpByServiceID, svcID)
	}
}

// specHasMatchingToServices returns true if the rule contains a ToServices rule which
// matches the provided service svcID/svc
func hasMatchingToServices(spec *api.Rule, ev serviceEvent) bool {
	if spec == nil {
		return false
	}
	for _, egress := range spec.Egress {
		for _, toService := range egress.ToServices {
			if sel := toService.K8sServiceSelector; sel != nil {
				if serviceSelectorMatches(sel, ev) {
					return true
				}
			} else if ref := toService.K8sService; ref != nil {
				if serviceRefMatches(ref, ev.name) {
					return true
				}
			}
		}
	}

	return false
}

// hasToServices returns true if the CNP contains a ToServices rule
func hasToServices(cnp *types.SlimCNP) bool {
	if specHasToServices(cnp.Spec) {
		return true
	}
	return slices.ContainsFunc(cnp.Specs, specHasToServices)
}

// specHasToServices returns true if the rule contains a ToServices rule
func specHasToServices(spec *api.Rule) bool {
	if spec == nil {
		return false
	}
	for _, egress := range spec.Egress {
		if len(egress.ToServices) > 0 {
			return true
		}
	}

	return false
}

type serviceDetailer interface {
	getNamespace() string
	getName() string
	getLabels() labels.Labels
}

// serviceSelectorMatches returns true if the ToServices k8sServiceSelector
// matches the labels of the provided service svc
func serviceSelectorMatches(sel *api.K8sServiceSelectorNamespace, svc serviceDetailer) bool {
	if !(sel.Namespace == svc.getNamespace() || sel.Namespace == "") {
		return false
	}
	ls := policytypes.NewLabelSelector(api.EndpointSelector(sel.Selector))
	r := policytypes.Matches(ls, labelsMatcher(svc.getLabels()))
	return r
}

type labelsMatcher labels.Labels

// Get implements labels.LabelMatcher; label source is ignored
func (l labelsMatcher) GetLabel(label *labels.Label) (value string) {
	v := l[label.Key]
	return v.Value
}

// Has implements labels.LabelMatcher.
func (l labelsMatcher) HasLabel(label *labels.Label) (exists bool) {
	_, ok := l[label.Key]
	return ok
}

// Lookup implements labels.LabelMatcher
func (l labelsMatcher) LookupLabel(label *labels.Label) (value string, exists bool) {
	v, ok := l[label.Key]
	return v.Value, ok
}

var _ labels.LabelMatcher = labelsMatcher{}

// serviceRefMatches returns true if the ToServices k8sService reference
// matches the name/namespace of the provided service svc
func serviceRefMatches(ref *api.K8sServiceNamespace, svcID loadbalancer.ServiceName) bool {
	return (ref.Namespace == svcID.Namespace() || ref.Namespace == "") &&
		ref.ServiceName == svcID.Name()
}

// serviceEndpoints stores the endpoints associated with a service
type serviceEndpoints struct {
	svc             *loadbalancer.Service
	backendPrefixes func() backendPrefixes
}

func (s serviceEndpoints) getLabels() labels.Labels { return s.svc.Labels }
func (s serviceEndpoints) getName() string          { return s.svc.Name.Name() }
func (s serviceEndpoints) getNamespace() string     { return s.svc.Name.Namespace() }

var _ serviceDetailer = serviceEndpoints{}

// newServiceEndpoints returns an initialized serviceEndpoints struct
func newServiceEndpoints(svc *loadbalancer.Service, txn statedb.ReadTxn, backends statedb.Table[*loadbalancer.Backend]) serviceEndpoints {
	return serviceEndpoints{
		svc: svc,
		backendPrefixes: sync.OnceValue(func() backendPrefixes {
			prefixes := backendPrefixes{}
			for be := range backends.List(txn, loadbalancer.BackendByServiceName(svc.Name)) {
				addr := be.Address.Addr()
				prefixes = append(prefixes, api.CIDR(netip.PrefixFrom(addr, addr.BitLen()).String()))
			}
			return prefixes
		}),
	}
}

// appendEndpoints appends all the endpoint as generated CIDRRules into the toCIDRSet
func appendEndpoints(toCIDRSet *api.CIDRRuleSlice, endpoints []api.CIDR) {
	for _, cidr := range endpoints {
		*toCIDRSet = append(*toCIDRSet, api.CIDRRule{
			Cidr:      cidr,
			Generated: true,
		})
	}
}

// appendSelector appends the service selector as a generated EndpointSelector
func appendSelector(toEndpoints *[]api.EndpointSelector, svcSelector map[string]string, namespace string) {
	selector := maps.Clone(svcSelector)
	selector[labels.LabelSourceK8sKeyPrefix+k8sConst.PodNamespaceLabel] = namespace
	endpointSelector := api.NewESFromMatchRequirements(selector, nil)
	endpointSelector.Generated = true

	*toEndpoints = append(*toEndpoints, endpointSelector)
}

// processRule parses the ToServices selectors in the provided rule and translates it to:
// - ToCIDRSet entries for services without selector
// - ToEndpoints entries for services with selector
func (s *serviceEndpoints) processRule(rule *api.Rule) (numMatches int) {
	if rule == nil {
		return
	}
	for i, egress := range rule.Egress {
		for _, toService := range egress.ToServices {
			if sel := toService.K8sServiceSelector; sel != nil {
				if serviceSelectorMatches(sel, s) {
					if len(s.svc.Selector) == 0 {
						appendEndpoints(&rule.Egress[i].ToCIDRSet, s.backendPrefixes())
					} else {
						appendSelector(&rule.Egress[i].ToEndpoints, s.svc.Selector, s.svc.Name.Namespace())
					}
					numMatches++
				}
			} else if ref := toService.K8sService; ref != nil {
				if serviceRefMatches(ref, s.svc.Name) {
					if len(s.svc.Selector) == 0 {
						appendEndpoints(&rule.Egress[i].ToCIDRSet, s.backendPrefixes())
					} else {
						appendSelector(&rule.Egress[i].ToEndpoints, s.svc.Selector, s.svc.Name.Namespace())
					}
					numMatches++
				}
			}
		}
	}
	return numMatches
}

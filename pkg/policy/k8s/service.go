// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"errors"
	"sync"

	"github.com/cilium/stream"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

// isSelectableService returns true if the service svc can be selected by a ToServices rule.
// Normally, only services without a label selector (i.e. empty services)
// are allowed as targets of a toServices rule.
// This is to minimize the chances of a pod IP being selected by this rule, which might
// cause conflicting entries in the ipcache.
//
// This requirement, however, is dropped for HighScale IPCache mode, because pod IPs are
// normally excluded from the ipcache regardless. Therefore, in HighScale IPCache mode,
// all services can be selected by ToServices.
func (p *policyWatcher) isSelectableService(svc *k8s.Service) bool {
	if svc == nil {
		return false
	}
	return p.config.EnableHighScaleIPcache || svc.IsExternal()
}

// onServiceEvent processes a ServiceNotification and (if necessary)
// recalculates all policies affected by this change.
func (p *policyWatcher) onServiceEvent(event k8s.ServiceNotification) {
	err := p.updateToServicesPolicies(event.ID, event.Service, event.OldService)
	if err != nil {
		p.log.WithError(err).WithFields(logrus.Fields{
			logfields.Event:     event.Action,
			logfields.ServiceID: event.ID,
		}).Warning("Failed to recalculate CiliumNetworkPolicy rules after service event")
	}
}

// updateToServicesPolicies is to be invoked when a service has changed (i.e. it was
// added, removed, its endpoints have changed, or its labels have changed).
// This function then checks if any of the known CNP/CCNPs are affected by this
// change, and recomputes them by calling resolveCiliumNetworkPolicyRefs.
func (p *policyWatcher) updateToServicesPolicies(svcID k8s.ServiceID, newSVC, oldSVC *k8s.Service) error {
	var errs []error

	// Bail out early if updated service is not selectable
	if !(p.isSelectableService(newSVC) || p.isSelectableService(oldSVC)) {
		return nil
	}

	// newService is true if this is the first time we observe this service
	newService := oldSVC == nil
	// changedService is true if the service label or selector has changed
	changedService := !newSVC.DeepEqual(oldSVC)

	// candidatePolicyKeys contains the set of policy names we need to process
	// for this service update. By default, we consider all policies with
	// a ToServices selector as candidates.
	candidatePolicyKeys := p.toServicesPolicies
	if !(newService || changedService) {
		// If the service definition itself has not changed, and it's not the
		// first time we process this service, we only need to check the
		// policies which are known to select the old version of the service
		candidatePolicyKeys = p.cnpByServiceID[svcID]
	}

	// Iterate over all policies potentially affected by this service update,
	// and re-resolve the policy refs for each.
	for key := range candidatePolicyKeys {
		cnp, ok := p.cnpCache[key]
		if !ok {
			p.log.WithFields(logrus.Fields{
				logfields.Key:       key,
				logfields.ServiceID: svcID,
			}).Error("BUG: Candidate policy for service update not found. Please report this bug to Cilium developers.")
			continue
		}

		// Skip policies which are not affected by this service update
		if !(p.cnpMatchesService(cnp, svcID, newSVC) ||
			(!newService && changedService && p.cnpMatchesService(cnp, svcID, oldSVC))) {
			continue
		}

		if p.config.Debug {
			p.log.WithFields(logrus.Fields{
				logfields.CiliumNetworkPolicyName: cnp.Name,
				logfields.K8sAPIVersion:           cnp.APIVersion,
				logfields.K8sNamespace:            cnp.Namespace,
				logfields.ServiceID:               svcID,
			}).Debug("Service updated or deleted, recalculating CiliumNetworkPolicy rules")
		}
		initialRecvTime := time.Now()

		resourceID := resourceIDForCiliumNetworkPolicy(key, cnp)

		errs = append(errs, p.resolveCiliumNetworkPolicyRefs(cnp, key, initialRecvTime, resourceID))
	}
	return errors.Join(errs...)
}

// resolveToServices translates all ToServices rules found in the provided CNP
// and to corresponding ToCIDRSet rules. Mutates the passed in cnp in place.
func (p *policyWatcher) resolveToServices(key resource.Key, cnp *types.SlimCNP) {
	// We consult the service cache to obtain the service endpoints
	// which are selected by the ToServices selectors found in the CNP.
	p.svcCache.ForEachService(func(svcID k8s.ServiceID, svc *k8s.Service, eps *k8s.Endpoints) bool {
		if !p.isSelectableService(svc) {
			return true // continue
		}

		// svcEndpoints caches the selected endpoints in case they are
		// referenced more than once by this CNP
		svcEndpoints := newServiceEndpoints(svcID, svc, eps)

		// This extracts the selected service endpoints from the rule
		// and translates it to a ToCIDRSet
		numMatches := svcEndpoints.processRule(cnp.Spec)
		for _, spec := range cnp.Specs {
			numMatches += svcEndpoints.processRule(spec)
		}

		// Mark the policy as selecting the service svcID. This allows us to
		// reduce the number of policy candidates in updateToServicesPolicies
		if numMatches > 0 {
			p.markCNPForService(key, svcID)
		} else {
			p.clearCNPForService(key, svcID)
		}

		return true
	})
}

// cnpMatchesService returns true if the cnp contains a ToServices rule which
// matches the provided service svcID/svc
func (p *policyWatcher) cnpMatchesService(cnp *types.SlimCNP, svcID k8s.ServiceID, svc *k8s.Service) bool {
	if !p.isSelectableService(svc) {
		return false
	}

	if hasMatchingToServices(cnp.Spec, svcID, svc) {
		return true
	}

	for _, spec := range cnp.Specs {
		if hasMatchingToServices(spec, svcID, svc) {
			return true
		}
	}

	return false
}

// markCNPForService marks that a policy (referred to by 'key') contains a
// ToServices selector selecting the service svcID
func (p *policyWatcher) markCNPForService(key resource.Key, svcID k8s.ServiceID) {
	svcMap, ok := p.cnpByServiceID[svcID]
	if !ok {
		svcMap = make(map[resource.Key]struct{}, 1)
		p.cnpByServiceID[svcID] = svcMap
	}

	svcMap[key] = struct{}{}
}

// clearCNPForService indicates that a policy (referred to by 'key') no longer
// selects the service svcID via a ToServices rule
func (p *policyWatcher) clearCNPForService(key resource.Key, svcID k8s.ServiceID) {
	delete(p.cnpByServiceID[svcID], key)
	if len(p.cnpByServiceID[svcID]) == 0 {
		delete(p.cnpByServiceID, svcID)
	}
}

// specHasMatchingToServices returns true if the rule contains a ToServices rule which
// matches the provided service svcID/svc
func hasMatchingToServices(spec *api.Rule, svcID k8s.ServiceID, svc *k8s.Service) bool {
	if spec == nil {
		return false
	}
	for _, egress := range spec.Egress {
		for _, toService := range egress.ToServices {
			if sel := toService.K8sServiceSelector; sel != nil {
				if serviceSelectorMatches(sel, svcID, svc) {
					return true
				}
			} else if ref := toService.K8sService; ref != nil {
				if serviceRefMatches(ref, svcID) {
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
	for _, spec := range cnp.Specs {
		if specHasToServices(spec) {
			return true
		}
	}
	return false
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

// serviceSelectorMatches returns true if the ToServices k8sServiceSelector
// matches the labels of the provided service svc
func serviceSelectorMatches(sel *api.K8sServiceSelectorNamespace, svcID k8s.ServiceID, svc *k8s.Service) bool {
	if !(sel.Namespace == svcID.Namespace || sel.Namespace == "") {
		return false
	}

	es := api.EndpointSelector(sel.Selector)
	es.SyncRequirementsWithLabelSelector()
	return es.Matches(labels.Set(svc.Labels))
}

// serviceRefMatches returns true if the ToServices k8sService reference
// matches the name/namespace of the provided service svc
func serviceRefMatches(ref *api.K8sServiceNamespace, svcID k8s.ServiceID) bool {
	return (ref.Namespace == svcID.Namespace || ref.Namespace == "") &&
		ref.ServiceName == svcID.Name
}

// serviceEndpoints stores the endpoints associated with a service
type serviceEndpoints struct {
	svcID k8s.ServiceID
	svc   *k8s.Service
	eps   *k8s.Endpoints

	valid  bool
	cached []api.CIDR
}

// newServiceEndpoints returns an initialized serviceEndpoints struct
func newServiceEndpoints(svcID k8s.ServiceID, svc *k8s.Service, eps *k8s.Endpoints) *serviceEndpoints {
	return &serviceEndpoints{
		svcID: svcID,
		svc:   svc,
		eps:   eps,
	}
}

// endpoints returns the service's endpoints as an []api.CIDR slice.
// It caches the result such that repeat invocations do not allocate.
func (s *serviceEndpoints) endpoints() []api.CIDR {
	if s.valid {
		return s.cached
	}

	prefixes := s.eps.Prefixes()
	s.cached = make([]api.CIDR, 0, len(prefixes))
	for _, prefix := range prefixes {
		s.cached = append(s.cached, api.CIDR(prefix.String()))
	}

	s.valid = true
	return s.cached
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

// processRule parses the ToServices selectors in the provided rule and translates
// it to ToCIDRSet entries
func (s *serviceEndpoints) processRule(rule *api.Rule) (numMatches int) {
	if rule == nil {
		return
	}
	for i, egress := range rule.Egress {
		for _, toService := range egress.ToServices {
			if sel := toService.K8sServiceSelector; sel != nil {
				if serviceSelectorMatches(sel, s.svcID, s.svc) {
					appendEndpoints(&rule.Egress[i].ToCIDRSet, s.endpoints())
					numMatches++
				}
			} else if ref := toService.K8sService; ref != nil {
				if serviceRefMatches(ref, s.svcID) {
					appendEndpoints(&rule.Egress[i].ToCIDRSet, s.endpoints())
					numMatches++
				}
			}
		}
	}
	return numMatches
}

type serviceQueue struct {
	mu    *lock.Mutex
	cond  *sync.Cond
	queue []k8s.ServiceNotification
}

func newServiceQueue() *serviceQueue {
	mu := new(lock.Mutex)
	return &serviceQueue{
		mu:    mu,
		cond:  sync.NewCond(mu),
		queue: []k8s.ServiceNotification{},
	}
}

func (q *serviceQueue) enqueue(item k8s.ServiceNotification) {
	q.mu.Lock()
	q.queue = append(q.queue, item)
	q.cond.Signal()
	q.mu.Unlock()
}

func (q *serviceQueue) signal() {
	q.mu.Lock()
	q.cond.Signal()
	q.mu.Unlock()
}

func (q *serviceQueue) dequeue(ctx context.Context) (item k8s.ServiceNotification, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for len(q.queue) == 0 {
		q.cond.Wait()

		// If ctx is cancelled, we return immediately
		if ctx.Err() != nil {
			return item, false
		}
	}

	item = q.queue[0]
	q.queue = q.queue[1:]

	return item, true
}

// serviceNotificationsQueue converts the observable src into a channel.
// When the provided context is cancelled the underlying subscription is
// cancelled and the channel is closed.
// In contrast to stream.ToChannel, this function has an unbounded buffer,
// meaning the consumer must always consume the channel (or cancel ctx)
func serviceNotificationsQueue(ctx context.Context, src stream.Observable[k8s.ServiceNotification]) <-chan k8s.ServiceNotification {
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan k8s.ServiceNotification)
	q := newServiceQueue()

	// This go routine is woken up whenever there a new item has been added to
	// queue and forwards it to ch. It exits when context ctx is cancelled.
	go func() {
		// Close downstream channel on exit
		defer close(ch)

		// Exit the for-loop below if the context is cancelled.
		// See https://pkg.go.dev/context#AfterFunc for a more detailed
		// explanation of this pattern
		cleanupCancellation := context.AfterFunc(ctx, q.signal)
		defer cleanupCancellation()

		for {
			item, ok := q.dequeue(ctx)
			if !ok {
				return
			}

			select {
			case ch <- item:
				continue
			case <-ctx.Done():
				return
			}
		}
	}()

	src.Observe(ctx,
		q.enqueue,
		func(err error) {
			cancel() // stops above go routine
		},
	)

	return ch
}

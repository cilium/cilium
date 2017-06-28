// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	log "github.com/Sirupsen/logrus"
	"github.com/go-openapi/runtime/middleware"
	"github.com/op/go-logging"
)

// GetCachedLabelList returns the cached labels for the given identity.
func (d *Daemon) GetCachedLabelList(ID policy.NumericIdentity) (labels.LabelArray, error) {
	// Check if we have the source security context in our local
	// consumable cache
	if c := d.consumableCache.Lookup(ID); c != nil {
		return c.LabelArray, nil
	}

	// No cache entry or labels not available, do full lookup of labels
	// via KV store
	lbls, err := d.LookupIdentity(ID)
	if err != nil {
		return nil, err
	}

	// ID is not associated with anything, skip...
	if lbls == nil {
		return nil, nil
	}

	l := lbls.Labels.ToSlice()

	return l, nil
}

func (d *Daemon) invalidateCache() {
	d.consumableCache.IncrementIteration()
}

// TriggerPolicyUpdates triggers policy updates for every daemon's endpoint.
// Returns a waiting group which signalizes when all endpoints are regenerated.
func (d *Daemon) TriggerPolicyUpdates(added []policy.NumericIdentity) *sync.WaitGroup {

	if len(added) == 0 {
		log.Debugf("Full policy recalculation triggered")
		d.invalidateCache()
	} else {
		log.Debugf("Partial policy recalculation triggered: %d", added)
		// FIXME: Invalidate only cache that is affected
		d.invalidateCache()
	}

	d.GetPolicyRepository().Mutex.RLock()
	d.EnablePolicyEnforcement()
	d.GetPolicyRepository().Mutex.RUnlock()
	return endpointmanager.TriggerPolicyUpdates(d)
}

// UpdateEndpointPolicyEnforcement returns whether policy enforcement needs to be
// enabled for the specified endpoint.
//
// Must be called with e.Consumable.Mutex and d.GetPolicyRepository().Mutex held
func (d *Daemon) UpdateEndpointPolicyEnforcement(e *endpoint.Endpoint) bool {
	if d.EnablePolicyEnforcement() {
		return true
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && d.conf.IsK8sEnabled() {
		// Check if rules match the labels for this endpoint.
		// If so, enable policy enforcement.
		return d.GetPolicyRepository().GetRulesMatching(e.Consumable.LabelArray)
	}
	return false
}

// EnablePolicyEnforcement returns whether policy enforcement needs to be
// enabled for the daemon.
//
// Must be called d.GetPolicyRepository().Mutex held
func (d *Daemon) EnablePolicyEnforcement() bool {
	if d.conf.EnablePolicy == endpoint.AlwaysEnforce {
		return true
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && !d.conf.IsK8sEnabled() {
		if d.GetPolicyRepository().NumRules() > 0 {
			// TODO - revisit setting Daemon endpoint.OptionPolicy here
			d.conf.Opts.Set(endpoint.OptionPolicy, true)
			return true
		} else {
			d.conf.Opts.Set(endpoint.OptionPolicy, false)
			return false
		}
	}
	return false
}

type getPolicyResolve struct {
	daemon *Daemon
}

func NewGetPolicyResolveHandler(d *Daemon) GetPolicyResolveHandler {
	return &getPolicyResolve{daemon: d}
}

func (d *Daemon) traceL4Egress(ctx policy.SearchContext, ports []*models.Port) api.Decision {
	ctx.To = ctx.From
	ctx.From = labels.LabelArray{}
	ctx.EgressL4Only = true

	ctx.PolicyTrace("\n")
	policy := d.policy.ResolveL4Policy(&ctx)
	verdict := policy.EgressCoversDPorts(ports)

	if len(ports) == 0 {
		ctx.PolicyTrace("L4 egress verdict: [no port context specified]\n")
	} else {
		ctx.PolicyTrace("L4 egress verdict: %s\n", verdict.String())
	}

	return verdict
}

func (d *Daemon) traceL4Ingress(ctx policy.SearchContext, ports []*models.Port) api.Decision {
	ctx.From = labels.LabelArray{}
	ctx.IngressL4Only = true

	ctx.PolicyTrace("\n")
	policy := d.policy.ResolveL4Policy(&ctx)
	verdict := policy.IngressCoversDPorts(ports)

	if len(ports) == 0 {
		ctx.PolicyTrace("L4 ingress verdict: [no port context specified]\n")
	} else {
		ctx.PolicyTrace("L4 ingress verdict: %s\n", verdict.String())
	}

	return verdict
}

func (h *getPolicyResolve) Handle(params GetPolicyResolveParams) middleware.Responder {
	log.Debugf("GET /policy/resolve request: %+v", params)

	d := h.daemon

	isPolicyEnforcementEnabled := true

	d.policy.Mutex.RLock()

	// If policy enforcement isn't enabled, then traffic is allowed.
	if d.conf.EnablePolicy == endpoint.NeverEnforce {
		isPolicyEnforcementEnabled = false
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && d.conf.IsK8sEnabled() {
		// If there are no rules matching the set of from / to labels provided in
		// the API request, that means that policy enforcement is not enabled
		// for the endpoints corresponding to said sets of labels; thus, we allow
		// traffic between these sets of labels, and do not enforce policy between them.
		if !(d.policy.GetRulesMatching(labels.NewSelectLabelArrayFromModel(params.IdentityContext.From)) ||
			d.policy.GetRulesMatching(labels.NewSelectLabelArrayFromModel(params.IdentityContext.To))) {
			isPolicyEnforcementEnabled = false
		}
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && !d.conf.IsK8sEnabled() {
		// If no rules are in the policy repository, then policy enforcement is
		// disabled; if there are rules, then policy enforcement is enabled.
		if d.policy.NumRules() == 0 {
			isPolicyEnforcementEnabled = false
		}
	}

	d.policy.Mutex.RUnlock()

	// Return allowed verdict if policy enforcement isn't enabled between the two sets of labels.
	if !isPolicyEnforcementEnabled {
		return NewGetPolicyResolveOK().WithPayload(&models.PolicyTraceResult{
			Verdict: api.Allowed.String(),
		})
	}

	// If we hit the following code, policy enforcement is enabled for at least
	// one of the endpoints corresponding to the provided sets of labels, or for
	// the daemon.
	buffer := new(bytes.Buffer)
	ctx := params.IdentityContext
	searchCtx := policy.SearchContext{
		Trace:   policy.TRACE_ENABLED,
		Logging: logging.NewLogBackend(buffer, "", 0),
		From:    labels.NewSelectLabelArrayFromModel(ctx.From),
		To:      labels.NewSelectLabelArrayFromModel(ctx.To),
		DPorts:  ctx.Dports,
	}
	if ctx.Verbose {
		searchCtx.Trace = policy.TRACE_VERBOSE
	}

	d.policy.Mutex.RLock()

	verdict := d.policy.AllowsRLocked(&searchCtx)
	searchCtx.PolicyTrace("L3 verdict: %s\n", verdict.String())

	// We only report the overall verdict as L4 inclusive if a port has
	// been specified
	if len(searchCtx.DPorts) != 0 {
		l4Egress := d.traceL4Egress(searchCtx, searchCtx.DPorts)
		l4Ingress := d.traceL4Ingress(searchCtx, searchCtx.DPorts)
		if l4Egress != api.Allowed || l4Ingress != api.Allowed {
			verdict = api.Denied
		}
	}

	d.policy.Mutex.RUnlock()

	result := models.PolicyTraceResult{
		Verdict: verdict.String(),
		Log:     buffer.String(),
	}

	return NewGetPolicyResolveOK().WithPayload(&result)
}

// AddOptions are options which can be passed to PolicyAdd
type AddOptions struct {
	// Replace if true indicates that existing rules with identical labels should be replaced
	Replace bool
}

func (d *Daemon) policyAdd(rules api.Rules, opts *AddOptions) (uint64, error) {
	d.policy.Mutex.Lock()
	defer d.policy.Mutex.Unlock()

	oldRules := api.Rules{}

	if opts != nil && opts.Replace {
		// Make copy of rules matching labels of new rules while
		// deleting them.
		for _, r := range rules {
			tmp := d.policy.SearchRLocked(r.Labels)
			if len(tmp) > 0 {
				d.policy.DeleteByLabelsLocked(r.Labels)
				oldRules = append(oldRules, tmp...)
			}
		}
	}

	rev, err := d.policy.AddListLocked(rules)
	if err != nil {
		// Restore old rules
		if len(oldRules) > 0 {
			if rev, err2 := d.policy.AddListLocked(oldRules); err2 != nil {
				log.Errorf("Error while restoring old rules after adding of new rules failed: %s", err2)
				log.Errorf("--- INCONSISTENT STATE OF POLICY ---")
				return rev, err
			}
		}

		return rev, err
	}

	return rev, nil
}

// PolicyAdd adds a slice of rules to the policy repository owned by the
// daemon.  Policy enforcement is automatically enabled if currently disabled if
// k8s is not enabled. Otherwise, if k8s is enabled, policy is enabled on the
// pods which are selected. Eventual changes in policy rules are propagated to
// all locally managed endpoints.
func (d *Daemon) PolicyAdd(rules api.Rules, opts *AddOptions) (uint64, *apierror.APIError) {
	log.Debugf("Policy Add Request: %+v", rules)

	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return 0, apierror.Error(PutPolicyFailureCode, err)
		}
	}

	rev, err := d.policyAdd(rules, opts)
	if err != nil {
		return 0, apierror.Error(PutPolicyFailureCode, err)
	}

	log.Info("New policy imported, regenerating...")
	d.TriggerPolicyUpdates([]policy.NumericIdentity{})

	return rev, nil
}

// PolicyDelete deletes the policy set in the given path from the policy tree.
// If cover256Sum is set it finds the rule with the respective coverage that
// rule from the node. If the path's node becomes ruleless it is removed from
// the tree.
func (d *Daemon) PolicyDelete(labels labels.LabelArray) (uint64, *apierror.APIError) {
	log.Debugf("Policy Delete Request: %+v", labels)

	// An error is only returned if a label filter was provided and then
	// not found A deletion request for all policy entries if no policied
	// are loaded should not fail.
	rev, deleted := d.policy.DeleteByLabels(labels)
	if deleted == 0 && len(labels) != 0 {
		return rev, apierror.New(DeletePolicyNotFoundCode, "policy not found")
	}

	go func() {
		// Store the consumables before we make any policy changes
		// to check which consumables were removed with the new policy.
		oldConsumables := d.consumableCache.GetConsumables()

		wg := d.TriggerPolicyUpdates([]policy.NumericIdentity{})

		// If daemon doesn't enforce policy then skip the cleanup
		// of CT entries.
		if d.PolicyEnforcement() == endpoint.NeverEnforce {
			return
		}

		// Wait for all policies to be updated so that
		// we can grab a fresh map of consumables.
		wg.Wait()

		newConsumables := d.consumableCache.GetConsumables()

		consumablesToRm := policy.ConsumablesInANotInB(oldConsumables, newConsumables)
		endpointmanager.Mutex.RLock()
		for _, ep := range endpointmanager.Endpoints {
			ep.Mutex.RLock()
			// If the policy is not being enforced then keep the CT
			// entries.
			if ep.SecLabel == nil ||
				!ep.Opts.IsEnabled(endpoint.OptionPolicy) {
				ep.Mutex.RUnlock()
				continue
			}
			epSecID := ep.SecLabel.ID

			ep.Mutex.RUnlock()

			idsToKeep := map[uint32]bool{}
			if consumers, ok := consumablesToRm[epSecID]; ok {
				for _, consumer := range consumers {
					idsToKeep[consumer.Uint32()] = true
				}
				if len(idsToKeep) != 0 {
					log.Debugf("Removing entries of EP %d: %+v", ep.ID, idsToKeep)
					endpointmanager.RmCTEntriesOf(!d.conf.IPv4Disabled, ep, idsToKeep)
				}
			}
		}
		endpointmanager.Mutex.RUnlock()
	}()
	return rev, nil
}

type deletePolicy struct {
	daemon *Daemon
}

func newDeletePolicyHandler(d *Daemon) DeletePolicyHandler {
	return &deletePolicy{daemon: d}
}

func (h *deletePolicy) Handle(params DeletePolicyParams) middleware.Responder {
	d := h.daemon
	lbls := labels.ParseSelectLabelArrayFromArray(params.Labels)
	rev, err := d.PolicyDelete(lbls)
	if err != nil {
		return apierror.Error(DeletePolicyFailureCode, err)
	}

	lbls = labels.ParseSelectLabelArrayFromArray([]string{})
	ruleList := d.policy.SearchRLocked(labels.LabelArray{})
	policy := &models.Policy{
		Revision: int64(rev),
		Policy:   policy.JSONMarshalRules(ruleList),
	}
	return NewDeletePolicyOK().WithPayload(policy)
}

type putPolicy struct {
	daemon *Daemon
}

func newPutPolicyHandler(d *Daemon) PutPolicyHandler {
	return &putPolicy{daemon: d}
}

func (h *putPolicy) Handle(params PutPolicyParams) middleware.Responder {
	d := h.daemon

	var rules api.Rules
	if err := json.Unmarshal([]byte(*params.Policy), &rules); err != nil {
		return NewPutPolicyInvalidPolicy()
	}

	rev, err := d.PolicyAdd(rules, nil)
	if err != nil {
		return apierror.Error(PutPolicyFailureCode, err)
	}

	policy := &models.Policy{
		Revision: int64(rev),
		Policy:   policy.JSONMarshalRules(rules),
	}
	return NewPutPolicyOK().WithPayload(policy)
}

type getPolicy struct {
	daemon *Daemon
}

func newGetPolicyHandler(d *Daemon) GetPolicyHandler {
	return &getPolicy{daemon: d}
}

func (h *getPolicy) Handle(params GetPolicyParams) middleware.Responder {
	d := h.daemon
	d.policy.Mutex.RLock()
	defer d.policy.Mutex.RUnlock()

	lbls := labels.ParseSelectLabelArrayFromArray(params.Labels)
	ruleList := d.policy.SearchRLocked(lbls)

	// Error if labels have been specified but no entries found, otherwise,
	// return empty list
	if len(ruleList) == 0 && len(lbls) != 0 {
		return NewGetPolicyNotFound()
	}

	policy := &models.Policy{
		Revision: int64(d.policy.GetRevision()),
		Policy:   policy.JSONMarshalRules(ruleList),
	}
	return NewGetPolicyOK().WithPayload(policy)
}

func (d *Daemon) PolicyInit() error {
	for k, v := range policy.ReservedIdentities {
		key := policy.NumericIdentity(v).String()
		lbl := labels.NewLabel(
			key, "", labels.LabelSourceReserved,
		)
		secLbl := policy.NewIdentity()
		secLbl.ID = v
		secLbl.AssociateEndpoint(lbl.String())
		secLbl.Labels[k] = lbl

		policyMapPath := bpf.MapPath(fmt.Sprintf("%sreserved_%d", policymap.MapName, int(v)))

		policyMap, _, err := policymap.OpenMap(policyMapPath)
		if err != nil {
			return fmt.Errorf("Could not create policy BPF map '%s': %s", policyMapPath, err)
		}

		c := d.consumableCache.GetOrCreate(v, secLbl)
		if c == nil {
			return fmt.Errorf("Unable to initialize consumable for %v", secLbl)
		}
		d.consumableCache.AddReserved(c)
		c.AddMap(policyMap)
	}

	return nil
}

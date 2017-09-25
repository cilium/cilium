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
	"strings"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/go-openapi/runtime/middleware"
	"github.com/op/go-logging"
	log "github.com/sirupsen/logrus"
)

// GetCachedLabelList returns the cached labels for the given identity.
func (d *Daemon) GetCachedLabelList(ID policy.NumericIdentity) (labels.LabelArray, error) {
	// Check if we have the source security context in our local
	// consumable cache
	if c := policy.GetConsumableCache().Lookup(ID); c != nil {
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

func invalidateCache() {
	policy.GetConsumableCache().IncrementIteration()
}

// TriggerPolicyUpdates triggers policy updates for every daemon's endpoint.
// Returns a waiting group which signalizes when all endpoints are regenerated.
func (d *Daemon) TriggerPolicyUpdates(added []policy.NumericIdentity) *sync.WaitGroup {
	if len(added) == 0 {
		log.Debugf("Full policy recalculation triggered")
		invalidateCache()
	} else {
		log.Debugf("Partial policy recalculation triggered: %d", added)
		// FIXME: Invalidate only cache that is affected
		invalidateCache()
	}
	return endpointmanager.TriggerPolicyUpdates(d)
}

// UpdateEndpointPolicyEnforcement returns whether policy enforcement needs to be
// enabled for the specified endpoint.
//
// Must be called with e.Consumable.Mutex and d.GetPolicyRepository().Mutex held.
func (d *Daemon) EnableEndpointPolicyEnforcement(e *endpoint.Endpoint) bool {
	// First check if policy enforcement should be enabled at the daemon level.
	// If policy enforcement is enabled for the daemon, then it has to be
	// enabled for the endpoint.

	config.EnablePolicyMU.RLock()
	defer config.EnablePolicyMU.RUnlock()
	daemonPolicyEnable := d.EnablePolicyEnforcement()
	if daemonPolicyEnable {
		return true
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && k8s.IsEnabled() {
		// Default mode + K8s means that if rules contain labels that match
		// this endpoint, then enable policy enforcement for this endpoint.
		return d.GetPolicyRepository().GetRulesMatching(e.Consumable.LabelArray)
	}
	// If policy enforcement isn't enabled for the daemon, or we are not running
	// in "default" mode in tandem with K8s, we do not enable policy enforcement
	// for the endpoint.
	// This means one of the following:
	// * daemon policy enforcement mode is 'never', so no policy enforcement
	//   should be applied to the specified endpoint.
	// * if we are not running K8s and are running in 'default' mode, we do not
	//   enable policy enforcement on a per-endpoint basis (i.e., outside of the
	//   scope of this function).
	return false
}

// EnablePolicyEnforcement returns whether policy enforcement needs to be
// enabled at the daemon-level.
//
// Must be called with d.GetPolicyRepository().Mutex and d.conf.EnablePolicyMU held.
func (d *Daemon) EnablePolicyEnforcement() bool {
	if d.conf.EnablePolicy == endpoint.AlwaysEnforce {
		return true
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && !k8s.IsEnabled() {
		if d.GetPolicyRepository().NumRules() > 0 {
			return true
		} else {
			return false
		}
	}
	// If we reach this case, one of the following situations is true:
	// * Policy enforcement is disabled for the daemon.
	// * We are running Cilium with default PolicyEnforcement mode and are
	// running Cilium in tandem with Kubernetes, which means that policy
	// enforcement is configured on a per-endpoint level.
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

	var policyEnforcementMsg string
	isPolicyEnforcementEnabled := true

	d.policy.Mutex.RLock()

	d.conf.EnablePolicyMU.RLock()
	// If policy enforcement isn't enabled, then traffic is allowed.
	if d.conf.EnablePolicy == endpoint.NeverEnforce {
		policyEnforcementMsg = "Policy enforcement is disabled for the daemon."
		isPolicyEnforcementEnabled = false
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && k8s.IsEnabled() {
		// If there are no rules matching the set of from / to labels provided in
		// the API request, that means that policy enforcement is not enabled
		// for the endpoints corresponding to said sets of labels; thus, we allow
		// traffic between these sets of labels, and do not enforce policy between them.
		if !(d.policy.GetRulesMatching(labels.NewSelectLabelArrayFromModel(params.IdentityContext.From)) ||
			d.policy.GetRulesMatching(labels.NewSelectLabelArrayFromModel(params.IdentityContext.To))) {
			policyEnforcementMsg = "Policy enforcement is disabled because " +
				"no rules in the policy repository match either of the provided " +
				"sets of labels."
			isPolicyEnforcementEnabled = false
		}
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && !k8s.IsEnabled() {
		// If no rules are in the policy repository, then policy enforcement is
		// disabled; if there are rules, then policy enforcement is enabled.
		if d.policy.NumRules() == 0 {
			policyEnforcementMsg = "Policy enforcement is disabled because " +
				"there are no rules in the policy repository."
			isPolicyEnforcementEnabled = false
		}
	}
	d.conf.EnablePolicyMU.RUnlock()

	d.policy.Mutex.RUnlock()

	// Return allowed verdict if policy enforcement isn't enabled between the two sets of labels.
	if !isPolicyEnforcementEnabled {
		buffer := new(bytes.Buffer)
		ctx := params.IdentityContext
		searchCtx := policy.SearchContext{
			From:    labels.NewSelectLabelArrayFromModel(ctx.From),
			Trace:   policy.TRACE_ENABLED,
			To:      labels.NewSelectLabelArrayFromModel(ctx.To),
			DPorts:  ctx.Dports,
			Logging: logging.NewLogBackend(buffer, "", 0),
		}
		if ctx.Verbose {
			searchCtx.Trace = policy.TRACE_VERBOSE
		}
		verdict := api.Allowed.String()
		searchCtx.PolicyTrace("Result: %s\n", strings.ToUpper(verdict))
		msg := fmt.Sprintf("%s\n  %s\n%s", searchCtx.String(), policyEnforcementMsg, buffer.String())
		return NewGetPolicyResolveOK().WithPayload(&models.PolicyTraceResult{
			Log:     msg,
			Verdict: verdict,
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
func (d *Daemon) PolicyAdd(rules api.Rules, opts *AddOptions) (uint64, error) {
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
func (d *Daemon) PolicyDelete(labels labels.LabelArray) (uint64, error) {
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
		oldConsumables := policy.GetConsumableCache().GetConsumables()

		wg := d.TriggerPolicyUpdates([]policy.NumericIdentity{})

		// If daemon doesn't enforce policy then skip the cleanup
		// of CT entries.
		if d.PolicyEnforcement() == endpoint.NeverEnforce {
			return
		}

		// Wait for all policies to be updated so that
		// we can grab a fresh map of consumables.
		wg.Wait()

		newConsumables := policy.GetConsumableCache().GetConsumables()

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
		log.Debugf("creating policy for %s", k)
		key := v.String()
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

		c := policy.GetConsumableCache().GetOrCreate(v, secLbl)
		if c == nil {
			return fmt.Errorf("Unable to initialize consumable for %v", secLbl)
		}
		policy.GetConsumableCache().AddReserved(c)
		c.AddMap(policyMap)
	}

	return nil
}

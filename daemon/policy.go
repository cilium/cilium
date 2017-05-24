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

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	log "github.com/Sirupsen/logrus"
	"github.com/go-openapi/runtime/middleware"
	"github.com/op/go-logging"
)

// GetCachedLabelList returns the cached labels for the given identity.
func (d *Daemon) GetCachedLabelList(ID policy.NumericIdentity) ([]*labels.Label, error) {
	// Check if we have the source security context in our local
	// consumable cache
	if c := d.consumableCache.Lookup(ID); c != nil {
		return c.LabelList, nil
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
func (d *Daemon) TriggerPolicyUpdates(added []policy.NumericIdentity) {

	if len(added) == 0 {
		log.Debugf("Full policy recalculation triggered")
		d.invalidateCache()
	} else {
		log.Debugf("Partial policy recalculation triggered: %d\n", added)
		// FIXME: Invalidate only cache that is affected
		d.invalidateCache()
	}

	d.endpointsMU.RLock()
	for k := range d.endpoints {
		go func(ep *endpoint.Endpoint) {
			ep.Mutex.RLock()
			epID := ep.StringIDLocked()
			ep.Mutex.RUnlock()
			policyChanges, err := ep.TriggerPolicyUpdates(d)
			if err != nil {
				log.Warningf("Error while handling policy updates for endpoint %s: %s\n",
					epID, err)
				ep.LogStatus(endpoint.Policy, endpoint.Failure, err.Error())
			} else {
				ep.LogStatusOK(endpoint.Policy, "Policy regenerated")
			}
			if policyChanges {
				ep.Regenerate(d)
			}
		}(d.endpoints[k])
	}
	d.endpointsMU.RUnlock()
}

// UpdatePolicyEnforcement returns whether policy enforcement needs to be
// enabled for the specified endpoint.
func (d *Daemon) UpdatePolicyEnforcement(e *endpoint.Endpoint) bool {
	if d.conf.EnablePolicy == endpoint.AlwaysEnforce {
		return true
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && !d.conf.IsK8sEnabled() {
		log.Infof("updatePolicyEnforcement: default enforcement, no k8s")
		if d.GetPolicyRepository().NumRules() > 0 {
			log.Infof("updatePolicyEnforcement: set to true, num rules > 0 ")
			// TODO - revisit setting Daemon endpoint.OptionPolicy here
			d.conf.Opts.Set(endpoint.OptionPolicy, true)
			return true
		} else {
			log.Infof("updatePolicyEnforcement: set to false, num rules == 0")
			d.conf.Opts.Set(endpoint.OptionPolicy, false)
			return false
		}
	} else if d.conf.EnablePolicy == endpoint.DefaultEnforcement && d.conf.IsK8sEnabled() {
		e.Mutex.RLock()
		// Convert to LabelArray so we can pass to Matches function later.
		var endpointLabels labels.LabelArray
		for _, lbl := range e.Consumable.LabelList {
			endpointLabels = append(endpointLabels, lbl)
		}
		e.Mutex.RUnlock()
		d.GetPolicyRepository().Mutex.RLock()
		defer d.GetPolicyRepository().Mutex.RUnlock()
		// Check if rules match the labels for this endpoint.
		// If so, enable policy enforcement.
		return d.GetPolicyRepository().GetRulesMatching(endpointLabels)
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
	d := h.daemon
	buffer := new(bytes.Buffer)
	ctx := params.IdentityContext
	searchCtx := policy.SearchContext{
		Trace:   policy.TRACE_ENABLED,
		Logging: logging.NewLogBackend(buffer, "", 0),
		From:    labels.NewLabelArrayFromModel(ctx.From),
		To:      labels.NewLabelArrayFromModel(ctx.To),
		DPorts:  ctx.Dports,
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

func (d *Daemon) policyAdd(rules api.Rules, opts *AddOptions) error {
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

	if err := d.policy.AddListLocked(rules); err != nil {
		// Restore old rules
		if len(oldRules) > 0 {
			if err2 := d.policy.AddListLocked(oldRules); err2 != nil {
				log.Errorf("Error while restoring old rules after adding of new rules failed: %s", err2)
				log.Errorf("--- INCONSISTENT STATE OF POLICY ---")
				return err
			}
		}

		return err
	}

	return nil
}

// PolicyAdd adds a slice of rules to the policy repository owned by the
// daemon.  Policy enforcement is automatically enabled if currently disabled if
// k8s is not enabled. Otherwise, if k8s is enabled, policy is enabled on the
// pods which are selected. Eventual changes in policy rules are propagated to
// all locally managed endpoints.
func (d *Daemon) PolicyAdd(rules api.Rules, opts *AddOptions) *apierror.APIError {
	log.Debugf("Policy Add Request: %+v", rules)

	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return apierror.Error(PutPolicyFailureCode, err)
		}
	}

	if err := d.policyAdd(rules, opts); err != nil {
		return apierror.Error(PutPolicyFailureCode, err)
	}

	log.Info("New policy imported, regenerating...")
	d.TriggerPolicyUpdates([]policy.NumericIdentity{})

	return nil
}

// PolicyDelete deletes the policy set in the given path from the policy tree.
// If cover256Sum is set it finds the rule with the respective coverage that
// rule from the node. If the path's node becomes ruleless it is removed from
// the tree.
func (d *Daemon) PolicyDelete(labels labels.LabelArray) *apierror.APIError {
	log.Debugf("Policy Delete Request: %+v", labels)

	// An error is only returned if a label filter was provided and then
	// not found A deletion request for all policy entries if no policied
	// are loaded should not fail.
	if d.policy.DeleteByLabels(labels) == 0 && len(labels) != 0 {
		return apierror.New(DeletePolicyNotFoundCode, "policy not found")
	}

	d.TriggerPolicyUpdates([]policy.NumericIdentity{})
	return nil
}

type deletePolicy struct {
	daemon *Daemon
}

func newDeletePolicyHandler(d *Daemon) DeletePolicyHandler {
	return &deletePolicy{daemon: d}
}

func (h *deletePolicy) Handle(params DeletePolicyParams) middleware.Responder {
	d := h.daemon
	lbls := labels.ParseLabelArrayFromArray(params.Labels)
	if err := d.PolicyDelete(lbls); err != nil {
		return apierror.Error(DeletePolicyFailureCode, err)
	}

	return NewDeletePolicyNoContent()
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

	if err := d.PolicyAdd(rules, nil); err != nil {
		return apierror.Error(PutPolicyFailureCode, err)
	}

	json := policy.JSONMarshalRules(rules)
	return NewPutPolicyOK().WithPayload(models.PolicyTree(json))
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

	lbls := labels.ParseLabelArrayFromArray(params.Labels)
	ruleList := d.policy.SearchRLocked(lbls)

	// Error if labels have been specified but no entries found, otherwise,
	// return empty list
	if len(ruleList) == 0 && len(lbls) != 0 {
		return NewGetPolicyNotFound()
	}

	json := policy.JSONMarshalRules(ruleList)
	return NewGetPolicyOK().WithPayload(models.PolicyTree(json))
}

func (d *Daemon) PolicyInit() error {
	for k, v := range policy.ReservedIdentities {
		key := policy.NumericIdentity(v).String()
		lbl := labels.NewLabel(
			key, "", common.ReservedLabelSource,
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

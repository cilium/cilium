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

	l4Egress := d.traceL4Egress(searchCtx, searchCtx.DPorts)
	l4Ingress := d.traceL4Ingress(searchCtx, searchCtx.DPorts)
	d.policy.Mutex.RUnlock()

	// We only report the overall verdict as L4 inclusive if a port has
	// been specified
	if len(searchCtx.DPorts) != 0 {
		if l4Egress != api.Allowed || l4Ingress != api.Allowed {
			verdict = api.Denied
		}
	}

	result := models.PolicyTraceResult{
		Verdict: verdict.String(),
		Log:     buffer.String(),
	}

	return NewGetPolicyResolveOK().WithPayload(&result)
}

func (d *Daemon) enablePolicyEnforcement() {
	d.conf.Opts.Set(endpoint.OptionPolicy, true)

	enablePolicy := map[string]string{endpoint.OptionPolicy: "enabled"}

	d.endpointsMU.RLock()
	for _, ep := range d.endpoints {
		ep.Mutex.Lock()
		optionsChanged := ep.ApplyOptsLocked(enablePolicy)
		ep.Mutex.Unlock()
		if optionsChanged {
			ep.RegenerateIfReady(d)
		}
	}
	d.endpointsMU.RUnlock()
}

// PolicyAdd adds a slice of rules to the policy repository owned by the
// daemon.  Policy enforcement is automatically enabled if currently disabled.
// Eventual changes in policy rules are propagated to all locally managed
// endpoints.
func (d *Daemon) PolicyAdd(rules api.Rules) *apierror.APIError {
	log.Debugf("Policy Add Request: %+v", rules)

	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return apierror.Error(PutPolicyPathFailureCode, err)
		}
	}

	// Enable policy if not already enabled
	if !d.conf.Opts.IsEnabled(endpoint.OptionPolicy) {
		d.enablePolicyEnforcement()
	}

	if err := d.policy.AddList(rules); err != nil {
		return apierror.Error(PutPolicyPathFailureCode, err)
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
	//log.Debugf("Policy Delete Request: %s, cover256Sum %s", path, cover256Sum)
	log.Debugf("Policy Delete Request: %+v", labels)

	//if cover256Sum != "" && len(cover256Sum) != policy.CoverageSHASize {
	//	return apierror.New(DeletePolicyPathInvalidCode,
	//		"invalid length of hash, must be %d", policy.CoverageSHASize)
	//}

	if d.policy.DeleteByLabels(labels) == 0 {
		return apierror.New(DeletePolicyPathNotFoundCode, "policy not found")
	}

	d.TriggerPolicyUpdates([]policy.NumericIdentity{})
	return nil
}

type deletePolicyPath struct {
	daemon *Daemon
}

func NewDeletePolicyPathHandler(d *Daemon) DeletePolicyPathHandler {
	return &deletePolicyPath{daemon: d}
}

func (h *deletePolicyPath) Handle(params DeletePolicyPathParams) middleware.Responder {
	d := h.daemon
	// FIXME
	if err := d.PolicyDelete(labels.LabelArray{}); err != nil {
		return apierror.Error(DeletePolicyPathFailureCode, err)
	}

	return NewDeletePolicyPathNoContent()
}

type putPolicyPath struct {
	daemon *Daemon
}

func NewPutPolicyPathHandler(d *Daemon) PutPolicyPathHandler {
	return &putPolicyPath{daemon: d}
}

func (h *putPolicyPath) Handle(params PutPolicyPathParams) middleware.Responder {
	d := h.daemon

	var rules api.Rules
	if err := json.Unmarshal([]byte(*params.Policy), &rules); err != nil {
		return NewPutPolicyPathInvalidPolicy()
	}

	if err := d.PolicyAdd(rules); err != nil {
		return apierror.Error(PutPolicyPathFailureCode, err)
	}

	json := policy.JSONMarshalRules(rules)
	return NewPutPolicyPathOK().WithPayload(models.PolicyTree(json))
}

type getPolicy struct {
	daemon *Daemon
}

func NewGetPolicyHandler(d *Daemon) GetPolicyHandler {
	return &getPolicy{daemon: d}
}

// Returns the entire policy tree
func (h *getPolicy) Handle(params GetPolicyParams) middleware.Responder {
	d := h.daemon
	return NewGetPolicyOK().WithPayload(models.PolicyTree(d.policy.GetJSON()))
}

type getPolicyPath struct {
	daemon *Daemon
}

func NewGetPolicyPathHandler(d *Daemon) GetPolicyPathHandler {
	return &getPolicyPath{daemon: d}
}

func (h *getPolicyPath) Handle(params GetPolicyPathParams) middleware.Responder {
	d := h.daemon
	d.policy.Mutex.RLock()
	defer d.policy.Mutex.RUnlock()

	// FIXME
	ruleList := d.policy.SearchRLocked(labels.LabelArray{})
	if len(ruleList) == 0 {
		return NewGetPolicyPathNotFound()
	}

	json := policy.JSONMarshalRules(ruleList)
	return NewGetPolicyPathOK().WithPayload(models.PolicyTree(json))
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

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
	"github.com/cilium/cilium/bpf/policymap"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/go-openapi/runtime/middleware"
	"github.com/op/go-logging"
)

func (d *Daemon) GetCachedLabelList(ID policy.NumericIdentity) ([]labels.Label, error) {
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
	d.consumableCache.Iteration++
	if d.consumableCache.Iteration == 0 {
		d.consumableCache.Iteration = 1
	}
}

func (d *Daemon) triggerPolicyUpdates(added []policy.NumericIdentity) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	if len(added) == 0 {
		log.Debugf("Full policy recalculation triggered")
		d.invalidateCache()
	} else {
		log.Debugf("Partial policy recalculation triggered: %d\n", added)
		// FIXME: Invalidate only cache that is affected
		d.invalidateCache()
	}

	log.Debugf("Iterating over endpoints...")

	for _, ep := range d.endpoints {
		log.Debugf("Triggering policy update for ep %s", ep.StringID())
		err := ep.TriggerPolicyUpdates(d)
		if err != nil {
			log.Warningf("Error while handling policy updates for endpoint %s: %s\n",
				ep.StringID(), err)
			ep.LogStatus(endpoint.Failure, err.Error())
		} else {
			ep.LogStatusOK("Policy regenerated")
		}
	}

	log.Debugf("End")
}

// PolicyCanConsume calculates if the ctx allows the consumer to be consumed. This public
// function returns a SearchContextReply with the consumable decision and the tracing log
// if ctx.Trace was set.
func (d *Daemon) PolicyCanConsume(ctx *policy.SearchContext) (*policy.SearchContextReply, error) {
	buffer := new(bytes.Buffer)
	if ctx.Trace != policy.TRACE_DISABLED {
		ctx.Logging = logging.NewLogBackend(buffer, "", 0)
	}
	scr := policy.SearchContextReply{}
	d.policy.Mutex.RLock()
	scr.Decision = d.policy.Allows(ctx)
	d.policy.Mutex.RUnlock()

	if ctx.Trace != policy.TRACE_DISABLED {
		scr.Logging = buffer.Bytes()
	}
	return &scr, nil
}

type getPolicyResolve struct {
	daemon *Daemon
}

func NewGetPolicyResolveHandler(d *Daemon) GetPolicyResolveHandler {
	return &getPolicyResolve{daemon: d}
}

func (h *getPolicyResolve) Handle(params GetPolicyResolveParams) middleware.Responder {
	d := h.daemon
	buffer := new(bytes.Buffer)
	ctx := params.IdentityContext
	search := policy.SearchContext{
		Trace:   policy.TRACE_ENABLED,
		Logging: logging.NewLogBackend(buffer, "", 0),
		From:    labels.NewLabelsFromModel(ctx.From).ToSlice(),
		To:      labels.NewLabelsFromModel(ctx.To).ToSlice(),
	}

	d.policy.Mutex.RLock()
	verdict := d.policy.Allows(&search)
	d.policy.Mutex.RUnlock()

	result := models.PolicyTraceResult{
		Verdict: verdict.String(),
		Log:     buffer.String(),
	}

	return NewGetPolicyResolveOK().WithPayload(&result)
}

func (d *Daemon) enablePolicyEnforcement() {
	d.conf.Opts.Set(endpoint.OptionPolicy, true)

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	enablePolicy := map[string]string{endpoint.OptionPolicy: "enabled"}

	for _, ep := range d.endpoints {
		if ep.ApplyOpts(enablePolicy) {
			ep.RegenerateIfReady(d)
		}
	}
}

func (d *Daemon) PolicyAdd(path string, node *policy.Node) *apierror.ApiError {
	log.Debugf("Policy Add Request: %s %+v", path, node)

	// Enable policy if not already enabled
	if !d.conf.Opts.IsEnabled(endpoint.OptionPolicy) {
		d.enablePolicyEnforcement()
	}

	if policyModified, err := d.policy.Add(path, node); err != nil {
		return apierror.Error(PutPolicyPathFailureCode, err)
	} else if policyModified {
		log.Info("New policy imported, regenerating...")
		d.triggerPolicyUpdates([]policy.NumericIdentity{})
	}

	return nil
}

// PolicyDelete deletes the policy set in the given path from the policy tree.
// If cover256Sum is set it finds the rule with the respective coverage that
// rule from the node. If the path's node becomes ruleless it is removed from
// the tree.
func (d *Daemon) PolicyDelete(path, cover256Sum string) *apierror.ApiError {
	log.Debugf("Policy Delete Request: %s, cover256Sum %s", path, cover256Sum)

	if cover256Sum != "" && len(cover256Sum) != policy.CoverageSHASize {
		return apierror.New(DeletePolicyPathInvalidCode,
			"invalid length of hash, must be %d", policy.CoverageSHASize)
	}

	if !d.policy.Delete(path, cover256Sum) {
		return apierror.New(DeletePolicyPathNotFoundCode, "policy not found")
	}

	d.triggerPolicyUpdates([]policy.NumericIdentity{})
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
	if err := d.PolicyDelete(params.Path, ""); err != nil {
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

	var node policy.Node
	if err := json.Unmarshal([]byte(*params.Policy), &node); err != nil {
		return NewPutPolicyPathInvalidPolicy()
	}

	if err := d.PolicyAdd(params.Path, &node); err != nil {
		return apierror.Error(PutPolicyPathFailureCode, err)
	}

	return NewPutPolicyPathOK().WithPayload(models.PolicyTree(node.JSONMarshal()))
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
	d.policy.Mutex.RLock()
	defer d.policy.Mutex.RUnlock()
	node := d.policy.Root
	if node == nil {
		node = &policy.Node{}
	}
	return NewGetPolicyOK().WithPayload(models.PolicyTree(node.JSONMarshal()))
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

	if node, _ := d.policy.Lookup(params.Path); node == nil {
		return NewGetPolicyPathNotFound()
	} else {
		return NewGetPolicyPathOK().WithPayload(models.PolicyTree(node.JSONMarshal()))
	}
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

		if c := d.consumableCache.GetOrCreate(v, secLbl); c == nil {
			return fmt.Errorf("Unable to initialize consumable for %v", secLbl)
		} else {
			d.consumableCache.AddReserved(c)
			c.AddMap(policyMap)
		}
	}

	return nil
}

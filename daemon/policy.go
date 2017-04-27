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

	searchCtx.PolicyTrace("L3 verdict: [%s]\n\n", verdict.String())
	if verdict != api.DENY {
		verdict = d.policy.AllowsL4RLocked(&searchCtx)

		searchCtx.PolicyTrace("\nL4 verdict: [%s]\n", verdict.String())
	} else {
		searchCtx.PolicyTrace("Ignoring L4 tracing result since L3 verdict is [%s]\n", verdict.String())
	}

	d.policy.Mutex.RUnlock()

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

// PolicyAtomicReplace does an atomic operation for the provided
// subPath.subNode, addPath.addNode.
// The "path", "node" tuple will have the same behaviour use as other similar
// Policy functions.
//
// sub[Path|Node] represents the node that will be subtracted from the tree,
// this means the rules inside this node will be removed from rules of the node
// with the same path in the policy tree.
//
// add[Path|Node] represents the node that will be added/merged to the tree,
// this means the rules inside this node will be append to an existing node with
// the same path or, in case it doesn't exist in the tree, the node itself will
// be created.
// Examples:
// tree
// {
//   "root": [{coverage: world, accept: id.foo},{coverage: host, accept: id.foo}],
//   "children": ["id": [{coverage: foo, accept: root.bar}]
// }
//
// PolicyAtomicReplace("root", Node{coverage: world, accept: id.foo}, "", nil)
// // Expected result:
// tree
// {
//   "root": [{coverage: host, accept: id.foo}],
//   "children": ["id": [{coverage: foo, accept: root.bar}]
// }
//
// PolicyAtomicReplace("root", Node{coverage: host, accept: id.foo},
//               "root", Node{name: "id", coverage: foo, accept: id.foo})
// // Expected result:
// tree
// {
//   "root": [],
//   "children": ["id": [{coverage: foo, accept: root.bar},
//                       {coverage: foo, accept: id.foo}]
// }
func (d *Daemon) PolicyAtomicReplace(subPath string, subNode *policy.Node,
	addPath string, addNode *policy.Node) *apierror.APIError {
	log.Debugf("Policy replace Request: %s %+v %s %+v", subPath, subNode, addPath, addNode)

	// Enable policy if not already enabled
	if !d.conf.Opts.IsEnabled(endpoint.OptionPolicy) {
		d.enablePolicyEnforcement()
	}

	if policyModified, err := d.policy.AtomicReplace(subPath, subNode, addPath, addNode); err != nil {
		return apierror.Error(PutPolicyPathFailureCode, err)
	} else if policyModified {
		log.Info("Policy modified imported, regenerating...")
		d.TriggerPolicyUpdates([]policy.NumericIdentity{})
	}

	return nil
}

func (d *Daemon) PolicyAdd(path string, node *policy.Node) *apierror.APIError {
	log.Debugf("Policy Add Request: %s %+v", path, node)

	// Enable policy if not already enabled
	if !d.conf.Opts.IsEnabled(endpoint.OptionPolicy) {
		d.enablePolicyEnforcement()
	}

	if policyModified, err := d.policy.Add(path, node); err != nil {
		return apierror.Error(PutPolicyPathFailureCode, err)
	} else if policyModified {
		log.Info("New policy imported, regenerating...")
		d.TriggerPolicyUpdates([]policy.NumericIdentity{})
	}

	return nil
}

// PolicyDelete deletes the policy set in the given path from the policy tree.
// If cover256Sum is set it finds the rule with the respective coverage that
// rule from the node. If the path's node becomes ruleless it is removed from
// the tree.
func (d *Daemon) PolicyDelete(path, cover256Sum string) *apierror.APIError {
	log.Debugf("Policy Delete Request: %s, cover256Sum %s", path, cover256Sum)

	if cover256Sum != "" && len(cover256Sum) != policy.CoverageSHASize {
		return apierror.New(DeletePolicyPathInvalidCode,
			"invalid length of hash, must be %d", policy.CoverageSHASize)
	}

	if !d.policy.Delete(path, cover256Sum) {
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

	node, _ := d.policy.LookupLocked(params.Path)
	if node == nil {
		return NewGetPolicyPathNotFound()
	}
	return NewGetPolicyPathOK().WithPayload(models.PolicyTree(node.JSONMarshal()))
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

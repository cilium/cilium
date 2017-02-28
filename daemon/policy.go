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

func validPath(path string) bool {
	return strings.HasPrefix(path, common.GlobalLabelPrefix)
}

// findNode returns node and its parent or an error
func (d *Daemon) findNode(path string) (*policy.Node, *policy.Node) {
	var parent *policy.Node

	newPath := strings.Replace(path, common.GlobalLabelPrefix, "", 1)
	if newPath == "" {
		return d.policy.Root, nil
	}

	current := d.policy.Root
	parent = nil

	for _, nodeName := range strings.Split(newPath, ".") {
		if nodeName == "" {
			continue
		}
		if child, ok := current.Children[nodeName]; ok {
			parent = current
			current = child
		} else {
			return nil, nil
		}
	}

	return current, parent
}

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
		log.Debugf("Triggering policy update for ep %+v", ep)
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

func (d *Daemon) policyAddNode(path string, node *policy.Node) (bool, error) {
	var (
		currNode, parentNode *policy.Node
		policyModified       bool
		err                  error
	)

	if node.Name == "" {
		path, node.Name = policy.SplitNodePath(path)
	} else if strings.Contains(node.Name, ".") && node.Name != common.GlobalLabelPrefix {
		path, node.Name = policy.SplitNodePath(path + "." + node.Name)
	}

	currNode, parentNode = d.findNode(path)
	log.Debugf("Policy currNode %+v, parentNode %+v", currNode, parentNode)

	// eg. path = io.cilium.lizards.foo.db and io.cilium.lizards doesn't exist
	if (currNode == nil && parentNode == nil) ||
		// eg. path = io.cilium.lizards.foo and io.cilium.lizards.foo doesn't exist
		(currNode == nil && parentNode != nil) {

		pn := policy.NewNode("", nil)
		policyModified, err = d.policyAddNode(path, pn)
		if err != nil {
			return false, err
		}
		currNode, parentNode = d.findNode(path)
		log.Debugf("Policy currNode %+v, parentNode %+v", currNode, parentNode)
	}
	// eg. path = io.cilium
	if currNode != nil && parentNode == nil {
		if currNode.Name == node.Name {
			node.Path()
			policyModified, err = currNode.Merge(node)
			if err != nil {
				return false, err
			}
		} else {
			policyModified, err = currNode.AddChild(node.Name, node)
			if err != nil {
				return false, err
			}
		}
	} else if currNode != nil && parentNode != nil {
		// eg. path = io.cilium.lizards.db exists
		policyModified, err = currNode.AddChild(node.Name, node)
		if err != nil {
			return false, err
		}
	}

	return policyModified, nil
}

func (d *Daemon) policyAdd(path string, node *policy.Node) (bool, error) {
	d.policy.Mutex.Lock()
	defer d.policy.Mutex.Unlock()

	if modified, err := d.policyAddNode(path, node); err != nil {
		return false, err
	} else if modified {
		return modified, node.ResolveTree()
	}

	return false, nil
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

	if !strings.HasPrefix(path, common.GlobalLabelPrefix) {
		return apierror.New(PutPolicyPathInvalidPathCode,
			"Invalid path %s: must start with %s", path, common.GlobalLabelPrefix)
	}

	// Enable policy if not already enabled
	if !d.conf.Opts.IsEnabled(endpoint.OptionPolicy) {
		d.enablePolicyEnforcement()
	}

	if policyModified, err := d.policyAdd(path, node); err != nil {
		return apierror.Error(PutPolicyPathFailureCode, err)
	} else if policyModified {
		log.Info("New policy imported, regenerating...")
		d.triggerPolicyUpdates([]policy.NumericIdentity{})
	}

	return nil
}

func (d *Daemon) deleteNode(node *policy.Node, parent *policy.Node) {
	if node == d.policy.Root {
		d.policy.Root = policy.NewNode(common.GlobalLabelPrefix, nil)
		d.policy.Root.Path()
	} else {
		delete(parent.Children, node.Name)
	}
}

// PolicyDelete deletes the policy set in the given path from the policy tree. If
// cover256Sum is set it finds the rule with the respective coverage that rule from the
// node. If the path's node becomes ruleless it is removed from the tree.
func (d *Daemon) PolicyDelete(path, cover256Sum string) *apierror.ApiError {
	log.Debugf("Policy Delete Request: %s, cover256Sum %s", path, cover256Sum)

	d.policy.Mutex.Lock()
	node, parent := d.findNode(path)
	if node == nil {
		d.policy.Mutex.Unlock()
		return apierror.New(DeletePolicyPathNotFoundCode, "Policy node not found")
	}

	// Deletion request of a specific rule of a node
	if cover256Sum != "" {
		if len(cover256Sum) != policy.CoverageSHASize {
			d.policy.Mutex.Unlock()
			return apierror.New(DeletePolicyPathInvalidCode,
				"Invalid length of hash, must be %d", policy.CoverageSHASize)
		}

		for i, pr := range node.Rules {
			if prCover256Sum, err := pr.CoverageSHA256Sum(); err == nil &&
				prCover256Sum == cover256Sum {
				node.Rules = append(node.Rules[:i], node.Rules[i+1:]...)

				// If the rule was the last remaining, delete the node
				if !node.HasRules() {
					d.deleteNode(node, parent)
				}

				d.policy.Mutex.Unlock()
				d.triggerPolicyUpdates([]policy.NumericIdentity{})
				return nil
			}
		}

		d.policy.Mutex.Unlock()
		return apierror.New(DeletePolicyPathNotFoundCode, "policy not found")
	}

	// Deletion request for entire node
	d.deleteNode(node, parent)
	d.policy.Mutex.Unlock()

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
	if !validPath(params.Path) {
		return apierror.New(PutPolicyPathInvalidPathCode,
			"path must have prefix %s", common.GlobalLabelPrefix)
	}

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

	if !validPath(params.Path) {
		return apierror.New(GetPolicyPathInvalidCode,
			"path must have prefix %s", common.GlobalLabelPrefix)
	}

	if node, _ := d.findNode(params.Path); node == nil {
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

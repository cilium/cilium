//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/cilium/cilium/bpf/policymap"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"

	"github.com/op/go-logging"
)

// findNode returns node and its parent or an error
func (d *Daemon) findNode(path string) (*types.PolicyNode, *types.PolicyNode, error) {
	var parent *types.PolicyNode

	if !strings.HasPrefix(path, common.GlobalLabelPrefix) {
		return nil, nil, fmt.Errorf("Invalid path %s: must start with %s", path, common.GlobalLabelPrefix)
	}

	newPath := strings.Replace(path, common.GlobalLabelPrefix, "", 1)
	if newPath == "" {
		return d.policyTree.Root, nil, nil
	}

	current := d.policyTree.Root
	parent = nil

	for _, nodeName := range strings.Split(newPath, ".") {
		if nodeName == "" {
			continue
		}
		if child, ok := current.Children[nodeName]; ok {
			parent = current
			current = child
		} else {
			return nil, nil, fmt.Errorf("Unable to find child %s of node %s in path %s", nodeName, current.Name, path)
		}
	}

	return current, parent, nil
}

func (d *Daemon) GetCachedLabelList(ID uint32) ([]types.Label, error) {
	// Check if we have the source security context in our local
	// consumable cache
	if c := types.LookupConsumable(ID); c != nil {
		return c.LabelList, nil
	}

	// No cache entry or labels not available, do full lookup of labels
	// via KV store
	lbls, err := d.GetLabels(ID)
	if err != nil {
		return nil, err
	}

	// ID is not associated with anything, skip...
	if lbls == nil {
		return nil, nil
	}

	l := make([]types.Label, len(lbls.Labels))

	idx := 0
	for k, v := range lbls.Labels {
		l[idx] = types.Label{Key: k, Value: v.Value, Source: v.Source}
		idx++
	}

	return l, nil
}

func (d *Daemon) evaluateConsumerSource(e *types.Endpoint, ctx *types.SearchContext, srcID uint32) error {
	var err error

	c := e.Consumable
	ctx.From, err = d.GetCachedLabelList(srcID)
	if err != nil {
		return err
	}

	log.Debugf("Evaluating policy for %+v", ctx)

	decision := d.policyCanConsume(ctx)
	// Only accept rules get stored
	if decision == types.ACCEPT {
		if !e.Opts.IsEnabled(types.OptionConntrack) {
			c.AllowConsumerAndReverse(srcID)
		} else {
			c.AllowConsumer(srcID)
		}
	}

	return nil
}

// Must be called with endpointsMU held
func (d *Daemon) regenerateConsumable(e *types.Endpoint) error {
	c := e.Consumable

	// Containers without a security label are not accessible
	if c.ID == 0 {
		log.Fatalf("Impossible: SecLabel == 0 when generating endpoint consumers")
		return nil
	}

	// Skip if policy for this consumable is already valid
	if c.Iteration == d.cacheIteration {
		log.Debugf("Policy for %d is already calculated, reusing...", c.ID)
		return nil
	}

	maxID, err := d.GetMaxLabelID()
	if err != nil {
		return err
	}

	ctx := types.SearchContext{
		To: c.LabelList,
	}

	d.conf.OptsMU.RLock()
	if d.conf.Opts.IsEnabled(OptionPolicyTracing) {
		ctx.Trace = types.TRACE_ENABLED
	}
	d.conf.OptsMU.RUnlock()

	// Mark all entries unused by denying them
	for k := range c.Consumers {
		c.Consumers[k].DeletionMark = true
	}

	d.policyTreeMU.RLock()
	// Check access from reserved consumables first
	for _, id := range d.reservedConsumables {
		if err := d.evaluateConsumerSource(e, &ctx, id.ID); err != nil {
			// This should never really happen
			// FIXME: clear policy because it is inconsistent
			break
		}
	}

	// Iterate over all possible assigned search contexts
	idx := common.FirstFreeLabelID
	for idx < maxID {
		if err := d.evaluateConsumerSource(e, &ctx, idx); err != nil {
			// FIXME: clear policy because it is inconsistent
			break
		}
		idx++
	}
	d.policyTreeMU.RUnlock()

	// Garbage collect all unused entries
	for _, val := range c.Consumers {
		if val.DeletionMark {
			val.DeletionMark = false
			c.BanConsumer(val.ID)
		}
	}

	// Result is valid until cache iteration advances
	c.Iteration = d.cacheIteration

	log.Debugf("New policy (iteration %d) for consumable %d: %+v\n", c.Iteration, c.ID, c.Consumers)

	return nil
}

func (d *Daemon) invalidateCache() {
	d.cacheIteration++
	if d.cacheIteration == 0 {
		d.cacheIteration = 1
	}
}

func (d *Daemon) checkEgressAccess(e *types.Endpoint, opts types.OptionMap, dstID uint32, opt string) {
	var err error

	ctx := types.SearchContext{
		From: e.Consumable.LabelList,
	}

	d.conf.OptsMU.RLock()
	if d.conf.Opts.IsEnabled(OptionPolicyTracing) {
		ctx.Trace = types.TRACE_ENABLED
	}
	d.conf.OptsMU.RUnlock()

	ctx.To, err = d.GetCachedLabelList(dstID)
	if err != nil {
		log.Warningf("Unable to get label list for ID %d, access for endpoint may be restricted\n", dstID)
		return
	}

	switch d.policyCanConsume(&ctx) {
	case types.ACCEPT, types.ALWAYS_ACCEPT:
		opts[opt] = true
	case types.DENY:
		opts[opt] = false
	}
}

func (d *Daemon) regenerateEndpointPolicy(e *types.Endpoint, regenerateEndpoint bool) error {
	if e.Consumable != nil {
		if err := d.regenerateConsumable(e); err != nil {
			return err
		}

		opts := make(types.OptionMap)

		d.checkEgressAccess(e, opts, uint32(types.ID_HOST), types.OptionAllowToHost)
		d.checkEgressAccess(e, opts, uint32(types.ID_WORLD), types.OptionAllowToWorld)

		if !e.ApplyOpts(opts) {
			// No changes have been applied, skip update
			return nil
		}

		if regenerateEndpoint {
			err := d.regenerateEndpoint(e)
			if err != nil {
				log.Warningf("Error while updating endpoint: %s\n", err)
			}
		}
	}

	return nil
}

func (d *Daemon) triggerPolicyUpdates(added []uint32) {
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

	for _, ep := range d.endpoints {
		d.regenerateEndpointPolicy(ep, true)
	}
}

// policyCanConsume calculates if the ctx allows the consumer to be consumed.
func (d *Daemon) policyCanConsume(ctx *types.SearchContext) types.ConsumableDecision {
	return d.policyTree.Allows(ctx)
}

// PolicyCanConsume calculates if the ctx allows the consumer to be consumed. This public
// function returns a SearchContextReply with the consumable decision and the tracing log
// if ctx.Trace was set.
func (d *Daemon) PolicyCanConsume(ctx *types.SearchContext) (*types.SearchContextReply, error) {
	buffer := new(bytes.Buffer)
	if ctx.Trace != types.TRACE_DISABLED {
		ctx.Logging = logging.NewLogBackend(buffer, "", 0)
	}
	scr := types.SearchContextReply{}
	d.policyTreeMU.RLock()
	scr.Decision = d.policyCanConsume(ctx)
	d.policyTreeMU.RUnlock()

	if ctx.Trace != types.TRACE_DISABLED {
		scr.Logging = buffer.Bytes()
	}
	return &scr, nil
}

func (d *Daemon) policyAdd(path string, node *types.PolicyNode) error {
	var (
		currNode, parentNode *types.PolicyNode
		err                  error
	)

	if node.Name == "" {
		path, node.Name = types.SplitPolicyNodePath(path)
	} else if strings.Contains(node.Name, ".") && node.Name != common.GlobalLabelPrefix {
		path, node.Name = types.SplitPolicyNodePath(path + "." + node.Name)
	}

	currNode, parentNode, err = d.findNode(path)
	if err != nil {
		return err
	}
	log.Debugf("Policy currNode %+v, parentNode %+v", currNode, parentNode)

	// eg. path = io.cilium.lizards.foo.db and io.cilium.lizards doesn't exist
	if (currNode == nil && parentNode == nil) ||
		// eg. path = io.cilium.lizards.foo and io.cilium.lizards.foo doesn't exist
		(currNode == nil && parentNode != nil) {

		pn := types.NewPolicyNode("", nil)
		if err := d.policyAdd(path, pn); err != nil {
			return err
		}
		currNode, parentNode, err = d.findNode(path)
		if err != nil {
			return err
		}
		log.Debugf("Policy currNode %+v, parentNode %+v", currNode, parentNode)
	}
	// eg. path = io.cilium
	if currNode != nil && parentNode == nil {
		if currNode.Name == node.Name {
			node.Path()
			if err := currNode.Merge(node); err != nil {
				return err
			}
		} else {
			if err := currNode.AddChild(node.Name, node); err != nil {
				return err
			}
		}
	} else if currNode != nil && parentNode != nil {
		// eg. path = io.cilium.lizards.db exists
		if err := currNode.AddChild(node.Name, node); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) PolicyAdd(path string, node *types.PolicyNode) error {
	log.Debugf("Policy Add Request: %s %+v", path, node)

	if !strings.HasPrefix(path, common.GlobalLabelPrefix) {
		return fmt.Errorf("the given path %q doesn't have the prefix %q", path, common.GlobalLabelPrefix)
	}

	d.policyTreeMU.Lock()
	if err := d.policyAdd(path, node); err != nil {
		d.policyTreeMU.Unlock()
		return err
	}
	if err := node.ResolveTree(); err != nil {
		d.policyTreeMU.Unlock()
		return err
	}
	d.policyTreeMU.Unlock()

	d.triggerPolicyUpdates([]uint32{})

	return nil
}

// PolicyDelete deletes the policy set in path from the policy tree.
func (d *Daemon) PolicyDelete(path string) error {
	log.Debugf("Policy Delete Request: %s", path)

	d.policyTreeMU.Lock()
	node, parent, err := d.findNode(path)
	if err != nil {
		d.policyTreeMU.Unlock()
		return err
	}
	if parent == nil {
		d.policyTree.Root = types.NewPolicyNode(common.GlobalLabelPrefix, nil)

		d.policyTree.Root.Path()
	} else {
		delete(parent.Children, node.Name)
	}
	d.policyTreeMU.Unlock()

	d.triggerPolicyUpdates([]uint32{})

	return nil
}

// PolicyGet returns the policy of the given path.
func (d *Daemon) PolicyGet(path string) (*types.PolicyNode, error) {
	log.Debugf("Policy Get Request: %s", path)
	d.policyTreeMU.RLock()
	node, _, err := d.findNode(path)
	d.policyTreeMU.RUnlock()
	return node, err
}

func (d *Daemon) PolicyInit() error {
	for k, v := range types.ResDec {

		key := types.ReservedID(uint32(v)).String()
		lbl := types.NewLabel(
			key, "", common.ReservedLabelSource,
		)
		secLbl := types.NewSecCtxLabel()
		secLbl.ID = uint32(v)
		secLbl.AddOrUpdateContainer(lbl.String())
		secLbl.Labels[k] = lbl

		policyMapPath := fmt.Sprintf("%sreserved_%d", common.PolicyMapPath, uint32(v))

		policyMap, _, err := policymap.OpenMap(policyMapPath)
		if err != nil {
			return fmt.Errorf("Could not create policy BPF map '%s': %s", policyMapPath, err)
		}

		if c := types.GetConsumable(uint32(v), secLbl); c == nil {
			return fmt.Errorf("Unable to initialize consumable for %v", secLbl)
		} else {
			d.reservedConsumables = append(d.reservedConsumables, c)
			c.AddMap(policyMap)
		}
	}

	return nil
}

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
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/op/go-logging"
)

// findNode returns node and its parent or an error
func (d *Daemon) findNode(path string) (*policy.Node, *policy.Node, error) {
	var parent *policy.Node

	if !strings.HasPrefix(path, common.GlobalLabelPrefix) {
		return nil, nil, fmt.Errorf("Invalid path %s: must start with %s", path, common.GlobalLabelPrefix)
	}

	newPath := strings.Replace(path, common.GlobalLabelPrefix, "", 1)
	if newPath == "" {
		return d.policy.Root, nil, nil
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
			return nil, nil, nil
		}
	}

	return current, parent, nil
}

func (d *Daemon) GetCachedLabelList(ID policy.NumericIdentity) ([]labels.Label, error) {
	// Check if we have the source security context in our local
	// consumable cache
	if c := d.consumableCache.Lookup(ID); c != nil {
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

	l := make([]labels.Label, len(lbls.Labels))

	idx := 0
	for k, v := range lbls.Labels {
		l[idx] = labels.Label{Key: k, Value: v.Value, Source: v.Source}
		idx++
	}

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

	for _, ep := range d.endpoints {
		err := ep.TriggerPolicyUpdates(d)
		if err != nil {
			log.Warningf("Error while handling policy updates for endpoint %s: %s\n",
				ep.String(), err)
			ep.LogStatus(endpoint.Failure, err.Error())
		} else {
			ep.LogStatusOK("Policy regenerated")
		}
	}
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

func (d *Daemon) policyAdd(path string, node *policy.Node) (bool, error) {
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

	currNode, parentNode, err = d.findNode(path)
	if err != nil {
		return false, err
	}
	log.Debugf("Policy currNode %+v, parentNode %+v", currNode, parentNode)

	// eg. path = io.cilium.lizards.foo.db and io.cilium.lizards doesn't exist
	if (currNode == nil && parentNode == nil) ||
		// eg. path = io.cilium.lizards.foo and io.cilium.lizards.foo doesn't exist
		(currNode == nil && parentNode != nil) {

		pn := policy.NewNode("", nil)
		policyModified, err = d.policyAdd(path, pn)
		if err != nil {
			return false, err
		}
		currNode, parentNode, err = d.findNode(path)
		if err != nil {
			return false, err
		}
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

func (d *Daemon) PolicyAdd(path string, node *policy.Node) error {
	log.Debugf("Policy Add Request: %s %+v", path, node)

	if !strings.HasPrefix(path, common.GlobalLabelPrefix) {
		return fmt.Errorf("the given path %q doesn't have the prefix %q", path, common.GlobalLabelPrefix)
	}

	var (
		err            error
		policyModified bool
	)

	d.policy.Mutex.Lock()
	defer func() {
		d.policy.Mutex.Unlock()
		if err == nil && policyModified {
			log.Info("New policy received, triggering updates...")
			d.triggerPolicyUpdates([]policy.NumericIdentity{})
		}
	}()

	policyModified, err = d.policyAdd(path, node)
	if err != nil || !policyModified {
		return err
	}
	err = node.ResolveTree()
	return err
}

// PolicyDelete deletes the policy set in the given path from the policy tree. If
// cover256Sum is set it finds the rule with the respective coverage that rule from the
// node. If the path's node becomes ruleless it is removed from the tree.
func (d *Daemon) PolicyDelete(path, cover256Sum string) (err error) {
	log.Debugf("Policy Delete Request: %s, cover256Sum %s", path, cover256Sum)

	d.policy.Mutex.Lock()
	defer func() {
		d.policy.Mutex.Unlock()
		if err == nil {
			d.triggerPolicyUpdates([]policy.NumericIdentity{})
		}
	}()

	var node, parent *policy.Node
	node, parent, err = d.findNode(path)
	if err != nil {
		return err
	}

	if len(cover256Sum) == policy.CoverageSHASize {
		ruleIndex := -1
		for i, pr := range node.Rules {
			if prCover256Sum, err := pr.CoverageSHA256Sum(); err == nil &&
				prCover256Sum == cover256Sum {
				ruleIndex = i
				break
			}
		}
		if ruleIndex == -1 {
			// rule with the given coverage was not found
			return
		}
		node.Rules = append(node.Rules[:ruleIndex], node.Rules[ruleIndex+1:]...)
		if node.Children != nil && len(node.Children) != 0 {
			return
		}
	}

	if parent == nil {
		d.policy.Root = policy.NewNode(common.GlobalLabelPrefix, nil)
		d.policy.Root.Path()
	} else {
		delete(parent.Children, node.Name)
	}

	return
}

// PolicyGet returns the policy of the given path.
func (d *Daemon) PolicyGet(path string) (*policy.Node, error) {
	log.Debugf("Policy Get Request: %s", path)
	d.policy.Mutex.RLock()
	node, _, err := d.findNode(path)
	d.policy.Mutex.RUnlock()
	return node, err
}

func (d *Daemon) PolicyInit() error {
	for k, v := range policy.ReservedIdentities {
		key := policy.NumericIdentity(v).String()
		lbl := labels.NewLabel(
			key, "", common.ReservedLabelSource,
		)
		secLbl := policy.NewIdentity()
		secLbl.ID = v
		secLbl.AddOrUpdateContainer(lbl.String())
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

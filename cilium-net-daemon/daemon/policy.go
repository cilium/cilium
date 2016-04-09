package daemon

import (
	"fmt"
	"strings"
	"sync"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"
)

// FIXME:
// Global tree, eventually this will turn into a cache with the real tree
// store in consul
var (
	tree        types.PolicyTree
	policyMutex sync.Mutex
)

// findNode returns node and its parent or an error
func findNode(path string) (*types.PolicyNode, *types.PolicyNode, error) {
	var parent *types.PolicyNode

	if strings.HasPrefix(path, common.GlobalLabelPrefix) == false {
		return nil, nil, fmt.Errorf("Invalid path %s: must start with %s", path, common.GlobalLabelPrefix)
	}

	newPath := strings.Replace(path, common.GlobalLabelPrefix, "", 1)
	if newPath == "" {
		return &tree.Root, nil, nil
	}

	current := &tree.Root
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

// RegenerateConsumerMap regenerates MAP of consumers for e. Must be called with
// endpointsMU held.
func (d *Daemon) RegenerateConsumerMap(e *types.Endpoint) error {
	// Containers without a security label are not accessible
	if e.SecLabel == 0 {
		return nil
	}

	maxID, err := d.GetMaxID()
	if err != nil {
		return err
	}

	secCtxLabels, err := d.GetLabels(int(e.SecLabel))
	if err != nil {
		return err
	}
	if secCtxLabels == nil {
		return nil
	}

	ctx := types.SearchContext{To: make([]types.Label, len(secCtxLabels.Labels))}

	idx := 0
	for k, v := range secCtxLabels.Labels {
		ctx.To[idx] = types.Label{Key: k, Value: v.Value, Source: v.Source}
		idx++
	}

	// Mark all entries unused by denying them
	for k, _ := range e.Consumers {
		e.Consumers[k].Decision = types.DENY
	}

	policyMutex.Lock()
	defer policyMutex.Unlock()

	for idx < maxID {
		srcSecCtxLabels, err := d.GetLabels(idx)
		if err != nil {
			break
		}
		if srcSecCtxLabels == nil {
			idx++
			continue
		}

		ctx.From = make([]types.Label, len(srcSecCtxLabels.Labels))

		idx2 := 0
		for k, v := range srcSecCtxLabels.Labels {
			ctx.From[idx2] = types.Label{Key: k, Value: v.Value, Source: v.Source}
			idx2++
		}

		log.Debugf("Building policy for context: %+v\n", ctx)

		decision := d.PolicyCanConsume(&ctx)
		// Only accept rules get stored
		if decision == types.ACCEPT {
			log.Debugf("Allowing direction %d -> %d\n", idx, e.SecLabel)
			e.AllowConsumer(idx)
			for _, r := range d.endpoints {
				if r.SecLabel == uint32(idx) {
					log.Debugf("Allowing reverse direction %d -> %d\n", e.SecLabel, idx)
					r.AllowConsumer(int(e.SecLabel))
				}
			}
		}
		idx++
	}

	// Garbage collect all unused entries
	for k, val := range e.Consumers {
		if val.Decision == types.DENY {
			e.BanConsumer(idx)
			delete(e.Consumers, k)
		}
	}

	log.Debugf("New policy map for ep %d: %+v\n", e.SecLabel, e.Consumers)

	return nil
}

// TriggerPolicyUpdates triggers policy updates for all endpoints in the host.
func (d *Daemon) TriggerPolicyUpdates(added []int) {
	log.Debugf("Triggering policy updates %+v", added)

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	for _, ep := range d.endpoints {
		d.RegenerateConsumerMap(ep)
	}
}

// PolicyCanConsume calculates if the ctx allows the consumer to be consumed.
func (d *Daemon) PolicyCanConsume(ctx *types.SearchContext) types.ConsumableDecision {
	return tree.Allows(ctx)
}

// PolicyAdd adds the policy with the given path to the node.
func (d *Daemon) PolicyAdd(path string, node types.PolicyNode) error {
	log.Debugf("Policy Add Request: %+v", &node)

	policyMutex.Lock()
	if parentNode, parent, err := findNode(path); err != nil {
		policyMutex.Unlock()
		return err
	} else {
		if parent == nil {
			tree.Root = node
		} else {
			parentNode.Children[node.Name] = &node
		}
	}
	policyMutex.Unlock()

	d.TriggerPolicyUpdates([]int{})

	return nil
}

// PolicyDelete deletes the policy set in path from the policy tree.
func (d *Daemon) PolicyDelete(path string) error {
	log.Debugf("Policy Delete Request: %s", path)

	policyMutex.Lock()
	if node, parent, err := findNode(path); err != nil {
		policyMutex.Unlock()
		return err
	} else {
		if parent == nil {
			tree.Root = types.PolicyNode{}
		} else {
			delete(parent.Children, node.Name)
		}
	}
	policyMutex.Unlock()

	d.TriggerPolicyUpdates([]int{})

	return nil
}

// PolicyGet returns the policy of the given path.
func (d *Daemon) PolicyGet(path string) (*types.PolicyNode, error) {
	log.Debugf("Policy Get Request: %s", path)
	node, _, err := findNode(path)
	return node, err
}

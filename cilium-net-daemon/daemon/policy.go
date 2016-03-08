package daemon

import (
	"fmt"
	"strings"

	"github.com/noironetworks/cilium-net/common/types"
)

// FIXME:
// Global tree, eventually this will turn into a cache with the real tree
// store in consul
var (
	tree types.PolicyTree
)

// Returns node and its parent or an error
func findNode(path string) (*types.PolicyNode, *types.PolicyNode, error) {
	var parent *types.PolicyNode

	if strings.HasPrefix(path, "io.cilium") == false {
		return nil, nil, fmt.Errorf("Invalid path %s: must start with io.cilium", path)
	}

	newPath := strings.Replace(path, "io.cilium", "", 1)
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

func (d Daemon) RegenerateConsumerMap(e *types.Endpoint) error {
	// Containers without a security label are not accessible
	if e.SecLabel == 0 {
		return nil
	}

	maxID, err := d.GetMaxID()
	if err != nil {
		return err
	}

	labels, err := d.GetLabels(int(e.SecLabel))
	if err != nil {
		return err
	}

	ctx := types.SearchContext{To: make([]types.Label, len(*labels))}

	idx := 0
	for k, v := range *labels {
		// FIXME labels layer to include source
		ctx.To[idx] = types.Label{Key: k, Value: v, Source: "cilium"}
		idx++
	}

	// Mark all entries unused by denying them
	for _, val := range e.Consumers {
		val.Decision = types.DENY
	}

	for idx < maxID {
		srcLabels, err := d.GetLabels(idx)
		if err != nil {
			break
		}
		if srcLabels == nil {
			idx++
			continue
		}

		ctx.From = make([]types.Label, len(*srcLabels))

		idx2 := 0
		for k, v := range *srcLabels {
			ctx.From[idx2] = types.Label{Key: k, Value: v, Source: "cilium"}
			idx2++
		}

		decision := d.PolicyCanConsume(&ctx)
		// Only accept rules get stored
		if decision == types.ACCEPT {
			e.AllowConsumer(idx)
		}
		idx++
	}

	// Garbage collect all unused entries
	for k, val := range e.Consumers {
		if val.Decision == types.DENY {
			delete(e.Consumers, k)
		}
	}

	return nil
}

func (d Daemon) TriggerPolicyUpdates(added []int) {
	d.endpointsMU.Lock()

	for _, ep := range d.endpoints {
		d.RegenerateConsumerMap(ep)
	}

	d.endpointsMU.Unlock()
}

func (d Daemon) PolicyCanConsume(ctx *types.SearchContext) types.ConsumableDecision {
	return tree.Allows(ctx)
}

func (d Daemon) PolicyAdd(path string, node types.PolicyNode) error {
	log.Debugf("Policy Add Request: %+v", &node)

	if parentNode, parent, err := findNode(path); err != nil {
		return err
	} else {
		if parent == nil {
			tree.Root = node
		} else {
			parentNode.Children[node.Name] = &node
		}
	}

	return nil
}

func (d Daemon) PolicyDelete(path string) error {
	log.Debugf("Policy Delete Request: %s", path)

	if node, parent, err := findNode(path); err != nil {
		return err
	} else {
		if parent == nil {
			tree.Root = types.PolicyNode{}
		} else {
			delete(parent.Children, node.Name)
		}
	}

	return nil
}

func (d Daemon) PolicyGet(path string) (*types.PolicyNode, error) {
	log.Debugf("Policy Get Request: %s", path)
	node, _, err := findNode(path)
	return node, err
}

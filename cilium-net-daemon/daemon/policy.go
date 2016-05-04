package daemon

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/noironetworks/cilium-net/bpf/policymap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/op/go-logging"
)

// FIXME:
// Global tree, eventually this will turn into a cache with the real tree
// store in consul
var (
	tree                types.PolicyTree
	policyMutex         sync.Mutex
	cacheIteration      = 1
	reservedConsumables = make([]*types.Consumable, 0)
)

// findNode returns node and its parent or an error
func findNode(path string) (*types.PolicyNode, *types.PolicyNode, error) {
	var parent *types.PolicyNode

	if strings.HasPrefix(path, common.GlobalLabelPrefix) == false {
		return nil, nil, fmt.Errorf("Invalid path %s: must start with %s", path, common.GlobalLabelPrefix)
	}

	newPath := strings.Replace(path, common.GlobalLabelPrefix, "", 1)
	if newPath == "" {
		return tree.Root, nil, nil
	}

	current := tree.Root
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

func (d *Daemon) EvaluateConsumerSource(c *types.Consumable, ctx *types.SearchContext, srcID uint32) error {
	ctx.From = nil

	// Check if we have the source security context in our local
	// consumable cache
	srcConsumable := types.LookupConsumable(srcID)
	if srcConsumable != nil {
		ctx.From = srcConsumable.LabelList
	}

	// No cache entry or labels not available, do full lookup of labels
	// via KV store
	if ctx.From == nil {
		lbls, err := d.GetLabels(srcID)
		if err != nil {
			return err
		}

		// ID is not associated with anything, skip...
		if lbls == nil {
			return nil
		}

		ctx.From = make([]types.Label, len(lbls.Labels))

		idx := 0
		for k, v := range lbls.Labels {
			ctx.From[idx] = types.Label{Key: k, Value: v.Value, Source: v.Source}
			idx++
		}
	}

	decision := d.policyCanConsume(ctx)
	// Only accept rules get stored
	if decision == types.ACCEPT {
		c.AllowConsumerAndReverse(srcID)
	}

	return nil
}

// Must be called with endpointsMU held
func (d *Daemon) RegenerateConsumable(c *types.Consumable) error {
	// Containers without a security label are not accessible
	if c.ID == 0 {
		log.Fatalf("Impossible: SecLabel == 0 when generating endpoint consumers")
		return nil
	}

	// Skip if policy for this consumable is already valid
	if c.Iteration == cacheIteration {
		log.Debugf("Policy for %d is already calculated, reusing...", c.ID)
		return nil
	}

	maxID, err := d.GetMaxID()
	if err != nil {
		return err
	}

	ctx := types.SearchContext{
		To: c.LabelList,
	}

	if d.enableTracing {
		ctx.Trace = types.TRACE_ENABLED
	}

	policyMutex.Lock()
	defer policyMutex.Unlock()

	// Mark all entries unused by denying them
	for k, _ := range c.Consumers {
		c.Consumers[k].DeletionMark = true
	}

	// Check access from reserved consumables first
	for _, id := range reservedConsumables {
		if err := d.EvaluateConsumerSource(c, &ctx, id.ID); err != nil {
			// This should never really happen
			// FIXME: clear policy because it is inconsistent
			break
		}
	}

	// Iterate over all possible assigned search contexts
	idx := common.FirstFreeID
	for idx < maxID {
		if err := d.EvaluateConsumerSource(c, &ctx, idx); err != nil {
			// FIXME: clear policy because it is inconsistent
			break
		}
		idx++
	}

	// Garbage collect all unused entries
	for _, val := range c.Consumers {
		if val.DeletionMark {
			val.DeletionMark = false
			c.BanConsumer(val.ID)
		}
	}

	// Result is valid until cache iteration advances
	c.Iteration = cacheIteration

	log.Debugf("New policy (iteration %d) for consumable %d: %+v\n", c.Iteration, c.ID, c.Consumers)

	return nil
}

func InvalidateCache() {
	cacheIteration++
	if cacheIteration == 0 {
		cacheIteration = 1
	}
}

func (d *Daemon) RegenerateEndpoint(e *types.Endpoint) error {
	if e.Consumable != nil {
		return d.RegenerateConsumable(e.Consumable)
	} else {
		return nil
	}
}

func (d *Daemon) TriggerPolicyUpdates(added []uint32) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	if len(added) == 0 {
		log.Debugf("Full policy recalculation triggered")
		InvalidateCache()
	} else {
		log.Debugf("Partial policy recalculation triggered: %d\n", added)
		// FIXME: Invalidate only cache that is affected
		InvalidateCache()
	}

	for _, ep := range d.endpoints {
		d.RegenerateEndpoint(ep)
	}
}

// policyCanConsume calculates if the ctx allows the consumer to be consumed.
func (d *Daemon) policyCanConsume(ctx *types.SearchContext) types.ConsumableDecision {
	return tree.Allows(ctx)
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
	scr.Decision = tree.Allows(ctx)
	if ctx.Trace != types.TRACE_DISABLED {
		scr.Logging = buffer.Bytes()
	}
	return &scr, nil
}

func (d *Daemon) PolicyAdd(path string, node *types.PolicyNode) error {
	if node.Name == "" {
		node.Name = path
	}

	log.Debugf("Policy Add Request: %+v", node)

	policyMutex.Lock()
	parentNode, parent, err := findNode(path)
	if err != nil {
		policyMutex.Unlock()
		return err
	}
	if parent == nil {
		tree.Root = node
	} else {
		if parent == nil {
			tree.Root = node
		} else {
			parentNode.Children[node.Name] = node
		}
	}
	policyMutex.Unlock()

	d.TriggerPolicyUpdates([]uint32{})

	return nil
}

// PolicyDelete deletes the policy set in path from the policy tree.
func (d *Daemon) PolicyDelete(path string) error {
	log.Debugf("Policy Delete Request: %s", path)

	policyMutex.Lock()
	node, parent, err := findNode(path)
	if err != nil {
		policyMutex.Unlock()
		return err
	}
	if parent == nil {
		tree.Root = &types.PolicyNode{}
	} else {
		if parent == nil {
			tree.Root = &types.PolicyNode{}
		} else {
			delete(parent.Children, node.Name)
		}
	}
	policyMutex.Unlock()

	d.TriggerPolicyUpdates([]uint32{})

	return nil
}

// PolicyGet returns the policy of the given path.
func (d *Daemon) PolicyGet(path string) (*types.PolicyNode, error) {
	log.Debugf("Policy Get Request: %s", path)
	node, _, err := findNode(path)
	return node, err
}

func PolicyInit() error {
	for k, v := range types.ResDec {
		lbl := types.SecCtxLabel{
			ID:       uint32(v),
			RefCount: 1,
			Labels:   map[string]*types.Label{},
		}
		policyMapPath := fmt.Sprintf("%sreserved_%d", common.PolicyMapPath, uint32(v))

		lbl.Labels[k] = &types.Label{Key: k, Source: common.ReservedLabelSource}

		policyMap, err := policymap.OpenMap(policyMapPath)
		if err != nil {
			return fmt.Errorf("Could not create policy BPF map '%s': %s", policyMapPath, err)
		}

		if c := types.GetConsumable(uint32(v), &lbl); c == nil {
			return fmt.Errorf("Unable to initialize consumable for %v", lbl)
		} else {
			reservedConsumables = append(reservedConsumables, c)
			c.AddMap(policyMap)
		}
	}

	return nil
}

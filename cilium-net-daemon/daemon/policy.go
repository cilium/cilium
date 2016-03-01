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

type SearchContext struct {
	from map[string]string
	to   map[string]string
}

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

func canConsume(root *types.PolicyNode, ctx *SearchContext) (bool, error) {

	for _, rule := range root.Rules {
		switch rule.(type) {
		case types.PolicyRuleConsumers:
			pr_c := rule.(types.PolicyRuleConsumers)
			log.Debugf("Policy Add Request: %+v", &pr_c)
			break
		}
	}

	// Need at least one partial match in destination labels to continue
	for _, child := range root.Children {
		fn := child.FullName()
		for k, _ := range ctx.to {
			if strings.HasPrefix(k, fn) {
				return canConsume(child, ctx)
			}
		}
	}

	return false, nil
}

func (d Daemon) PolicyCanConsume(ctx *SearchContext) (bool, error) {
	return canConsume(&tree.Root, ctx)
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

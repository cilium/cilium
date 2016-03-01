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

	path = strings.Replace(path, "io.cilium", "", 1)
	current := &tree.Root
	parent = nil

	for _, nodeName := range strings.Split(path, ".") {
		if child, ok := current.Children[nodeName]; ok {
			parent = current
			current = child
		} else {
			return nil, nil, fmt.Errorf("Unable to find node %s in path %s", nodeName, path)
		}
	}

	return current, parent, nil
}

func (d Daemon) PolicyAdd(path string, node types.PolicyNode) error {
	log.Debugf("Policy Add Request: %+v", &node)

	if node, parent, err := findNode(path); err != nil {
		return err
	} else {
		if parent == nil {
			log.Debugf("Replacing root")
			tree.Root = *node
		} else {
			node.Children[node.Name] = node
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

	log.Debugf("Found node: %+v", node)

	return node, err
}

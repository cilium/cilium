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

// Return child of node with given name
func findChild(name string, node *types.PolicyNode) *types.PolicyNode {
	for _, leaf := range node.Childs {
		if leaf.Name == name {
			return &leaf
		}
	}

	return nil
}

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
		if child := findChild(nodeName, current); child == nil {
			return nil, nil, fmt.Errorf("Unable to find node %s in path %s", nodeName, path)
		} else {
			parent = current
			current = child
		}
	}

	return current, parent, nil
}

func (d Daemon) PolicyAdd(path string, node types.PolicyNode) error {
	if path == "" {
		tree.Root = node
		return nil
	}

	if node, _, err := findNode(path); err != nil {
		return err
	} else {
		*node = types.PolicyNode{}

	}

	return nil
}

func (d Daemon) PolicyDelete(path string) error {
	if path == "" {
		// delete entire tree
		tree.Root = types.PolicyNode{}
		return nil
	}

	if node, _, err := findNode(path); err != nil {
		return err
	} else {
		*node = types.PolicyNode{}
	}

	return nil
}

func (d Daemon) PolicyGet(path string) (*types.PolicyNode, error) {
	if path == "" {
		return &tree.Root, nil
	} else {
		node, _, err := findNode(path)
		return node, err
	}
}

/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package yaml

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ValueInMapping finds the value node with the corresponding string key
// in the given mapping node.  If the given node is not a mapping, an
// error will be returned.
func ValueInMapping(root *yaml.Node, key string) (*yaml.Node, error) {
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("unexpected non-mapping node")
	}

	for i := 0; i < len(root.Content)/2; i++ {
		keyNode := root.Content[i*2]
		if keyNode.Value == key {
			return root.Content[i*2+1], nil
		}
	}
	return nil, nil
}

// asCloseAsPossible goes as deep on the given path as possible, returning the
// last node that existed from the given path in the given tree of mapping
// nodes, as well as the rest of the path that could not be fetched, if any.
func asCloseAsPossible(root *yaml.Node, path ...string) (*yaml.Node, []string, error) {
	if root == nil {
		return nil, path, nil
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}

	currNode := root
	for ; len(path) > 0; path = path[1:] {
		if currNode.Kind != yaml.MappingNode {
			return nil, nil, fmt.Errorf("unexpected non-mapping (%v) before path %v", currNode.Kind, path)
		}

		nextNode, err := ValueInMapping(currNode, path[0])
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get next node in path %v: %w", path, err)
		}

		if nextNode == nil {
			// we're as close as possible
			break
		}

		currNode = nextNode
	}

	return currNode, path, nil
}

// GetNode gets the node at the given path in the given sequence of mapping
// nodes, or, if it doesn't exist, returning false.
func GetNode(root *yaml.Node, path ...string) (*yaml.Node, bool, error) {
	resNode, restPath, err := asCloseAsPossible(root, path...)
	if err != nil {
		return nil, false, err
	}
	// more path means the node didn't exist
	if len(restPath) != 0 {
		return nil, false, nil
	}
	return resNode, true, nil
}

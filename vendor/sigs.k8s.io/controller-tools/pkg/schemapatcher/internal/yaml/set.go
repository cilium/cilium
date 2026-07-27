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

// SetNode sets the given path to the given yaml Node, creating mapping nodes along the way.
func SetNode(root *yaml.Node, val yaml.Node, path ...string) error {
	currNode, path, err := asCloseAsPossible(root, path...)
	if err != nil {
		return err
	}

	if len(path) > 0 {
		if currNode.Kind != yaml.MappingNode {
			return fmt.Errorf("unexpected non-mapping before path %v", path)
		}

		for ; len(path) > 0; path = path[1:] {
			keyNode := yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle, Value: path[0]}
			nextNode := &yaml.Node{Kind: yaml.MappingNode}
			currNode.Content = append(currNode.Content, &keyNode, nextNode)

			currNode = nextNode
		}
	}

	*currNode = val
	return nil
}

// DeleteNode deletes the node at the given path in the given tree of mapping nodes.
// It's a noop if the path doesn't exist.
func DeleteNode(root *yaml.Node, path ...string) error {
	if len(path) == 0 {
		return fmt.Errorf("must specify a path to delete")
	}
	pathToParent, keyToDelete := path[:len(path)-1], path[len(path)-1]
	parentNode, path, err := asCloseAsPossible(root, pathToParent...)
	if err != nil {
		return err
	}
	if len(path) > 0 {
		// no-op, parent node doesn't exist
		return nil
	}

	if parentNode.Kind != yaml.MappingNode {
		return fmt.Errorf("unexpected non-mapping node")
	}

	for i := 0; i < len(parentNode.Content)/2; i++ {
		keyNode := parentNode.Content[i*2]
		if keyNode.Value == keyToDelete {
			parentNode.Content = append(parentNode.Content[:i*2], parentNode.Content[i*2+2:]...)
			return nil
		}
	}

	// no-op, key not found in parent node
	return nil
}

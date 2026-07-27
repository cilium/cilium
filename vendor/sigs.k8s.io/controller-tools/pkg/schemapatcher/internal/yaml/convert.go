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
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ToYAML converts some object that serializes to JSON into a YAML node tree.
// It's useful since it pays attention to JSON tags, unlike yaml.Unmarshal or
// yaml.Node.Decode.
func ToYAML(rawObj any) (*yaml.Node, error) {
	if rawObj == nil {
		return &yaml.Node{Kind: yaml.ScalarNode, Value: "null", Tag: "!!null"}, nil
	}

	rawJSON, err := json.Marshal(rawObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object: %w", err)
	}

	var out yaml.Node
	if err := yaml.Unmarshal(rawJSON, &out); err != nil {
		return nil, fmt.Errorf("unable to unmarshal marshalled object: %w", err)
	}
	return &out, nil
}

// changeAll calls the given callback for all nodes in
// the given YAML node tree.
func changeAll(root *yaml.Node, cb func(*yaml.Node)) {
	cb(root)
	for _, child := range root.Content {
		changeAll(child, cb)
	}
}

// SetStyle sets the style for all nodes in the given
// node tree to the given style.
func SetStyle(root *yaml.Node, style yaml.Style) {
	changeAll(root, func(node *yaml.Node) {
		node.Style = style
	})
}

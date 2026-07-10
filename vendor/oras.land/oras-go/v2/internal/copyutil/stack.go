/*
Copyright The ORAS Authors.
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

package copyutil

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// NodeInfo represents information of a node that is being visited in
// ExtendedCopy.
type NodeInfo struct {
	// Node represents a node in the graph.
	Node ocispec.Descriptor
	// Depth represents the depth of the node in the graph.
	Depth int
}

// Stack represents a stack data structure that is used in ExtendedCopy for
// storing node information.
type Stack []NodeInfo

// IsEmpty returns true if the stack is empty, otherwise returns false.
func (s *Stack) IsEmpty() bool {
	return len(*s) == 0
}

// Push pushes an item to the stack.
func (s *Stack) Push(i NodeInfo) {
	*s = append(*s, i)
}

// Pop pops the top item out of the stack.
func (s *Stack) Pop() (NodeInfo, bool) {
	if s.IsEmpty() {
		return NodeInfo{}, false
	}

	last := len(*s) - 1
	top := (*s)[last]
	*s = (*s)[:last]
	return top, true
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

const (
	templateHostEndpointID = uint64(0xffff)
)

var (
	endpointID = templateHostEndpointID
)

// GetLabels returns the labels of this node.
func GetLabels() map[string]string {
	return getLocalNode().Labels
}

// SetLabels sets the labels of this node.
func SetLabels(l map[string]string) {
	localNode.Update(func(n *LocalNode) {
		n.Labels = l
	})
}

// SetAnnotations sets the annotations for this node.
func SetAnnotations(a map[string]string) {
	localNode.Update(func(n *LocalNode) {
		n.Annotations = a
	})
}

// SetMultiAttributes allows the caller to set multiple attributes
// on the LocalNode by passing a function which modifies LocalNode
// directly.
//
// This is useful when you need to update more then one attribute at once
// but do not want to trigger Observers more then once.
func SetMultiAttributes(f func(n *LocalNode)) {
	localNode.Update(f)
}

// GetEndpointID returns the ID of the host endpoint for this node.
func GetEndpointID() uint64 {
	return endpointID
}

// SetEndpointID sets the ID of the host endpoint this node.
func SetEndpointID(id uint64) {
	endpointID = id
}

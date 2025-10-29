// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

// Return if given node is present in cache
func (c *CESCache) hasNode(nodeName NodeName) bool {
	_, ok := c.nodeData[nodeName]
	return ok
}

// Return stored encryption key for node.
func (c *CESCache) getEncryptionKey(nodeName NodeName) (EncryptionKey, bool) {
	if nodeData, ok := c.nodeData[nodeName]; ok {
		return nodeData.key, true
	}
	return 0, false
}

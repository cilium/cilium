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

// Return if given CID is present in cache
func (c *CESCache) hasCID(cid CID) bool {
	_, ok := c.cidToGidLabels[cid]
	return ok
}

// Return the selected CID for the given GID labels
func (c *CESCache) GetSelectedId(gid Labels) (CID, bool) {
	if gidData, ok := c.globalIdLabelsToCIDSet[gid]; ok {
		if gidData.selectedID != "" {
			return gidData.selectedID, true
		}
	}
	return "", false
}

// Return the total number of CESs.
func (c *CESCache) getCESCount() int {
	return len(c.cesData)
}

// Return if the given CEP is present in cache
func (c *CESCache) hasCEP(cepName CEPName) bool {
	_, ok := c.cepData[cepName]
	return ok
}

// Return total number of CEPs stored in cache
func (c *CESCache) countCEPs() int {
	return len(c.cepData)
}

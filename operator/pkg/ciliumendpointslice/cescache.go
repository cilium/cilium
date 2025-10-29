// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"github.com/cilium/cilium/pkg/lock"
	"k8s.io/apimachinery/pkg/util/sets"
)

type NodeName string
type EncryptionKey int

// NodeData contains information about the node; the set of coreceps on
// the node and the known encryption key associated with the node.
type NodeData struct {
	ceps sets.Set[CEPName]
	key  EncryptionKey
}

func NewNodeData() *NodeData {
	return &NodeData{
		ceps: sets.New[CEPName](),
	}
}

type CESCache struct {
	mutex lock.RWMutex

	// nodeData is used to map node name to all CiliumEndpoints on the node
	// and the known encryption key associated with it
	nodeData map[NodeName]*NodeData
}

// Creates and intializes the new CESCache
func newCESCache() *CESCache {
	return &CESCache{
		nodeData: make(map[NodeName]*NodeData),
	}
}

// Update encryption key for node and return all affected CES whose CEPs are on that node.
func (c *CESCache) insertNode(nodeName NodeName, encryptionKey EncryptionKey) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.nodeData[nodeName]; !ok {
		c.nodeData[nodeName] = NewNodeData()
		c.nodeData[nodeName].key = encryptionKey
		return nil
	}

	if c.nodeData[nodeName].key != encryptionKey {
		c.nodeData[nodeName].key = encryptionKey
		return c.getCESForCEPs(c.nodeData[nodeName].ceps)
	}
	return nil
}

// Remove node from cache and return affected CESs
func (c *CESCache) deleteNode(nodeName NodeName) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if nodeData, ok := c.nodeData[nodeName]; ok {
		// TODO: Clean up node state in CEPData
		cesKeys := c.getCESForCEPs(nodeData.ceps)
		delete(c.nodeData, nodeName)
		return cesKeys
	}
	return nil
}

// Return if given node is present in cache
func (c *CESCache) hasNode(nodeName NodeName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.nodeData[nodeName]
	return ok
}

// Return CES keys for the given CEPs. Caller must hold the cache lock.
func (c *CESCache) getCESForCEPs(ceps sets.Set[CEPName]) []CESKey {
	// TODO: Implement when CEP/CES state is tracked in cache
	return nil
}

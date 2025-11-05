// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCESCacheNodeState(t *testing.T) {
	testCases := []struct {
		name          string
		nodeName      NodeName
		encryptionKey EncryptionKey
		count         int
	}{
		{
			name:          "Insert Node - 1",
			nodeName:      NodeName("node1"),
			encryptionKey: EncryptionKey(1),
			count:         1,
		},
		{
			name:          "Insert Node - 2",
			nodeName:      NodeName("node2"),
			encryptionKey: EncryptionKey(2),
			count:         2,
		},
		{
			name:          "Insert Same Node with New Key",
			nodeName:      NodeName("node1"),
			encryptionKey: EncryptionKey(3),
			count:         2,
		},
	}
	cmap := newCESCache()

	// Insert new Nodes in CES cache and check its total count
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertNode(NodeName(tc.nodeName), tc.encryptionKey)
			assert.Equal(t, len(cmap.nodeData), tc.count, "Number of nodes in cmap should match with Count")
			nd, ok := cmap.nodeData[tc.nodeName]
			assert.True(t, ok, "Node name should present in cmap")
			assert.Equal(t, nd.key, tc.encryptionKey, "Encryption key for node should match")
		})
	}

	// Insert and remove Nodes in CES cache and check for any stale entries present in CES cache.
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertNode(NodeName(tc.nodeName), tc.encryptionKey)
			cmap.deleteNode(NodeName(tc.nodeName))
			assert.False(t, cmap.hasNode(tc.nodeName), "Node name is removed from cache, so it shouldn't be in cache")
		})
	}

	assert.Empty(t, cmap.nodeData)
}

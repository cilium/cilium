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
		cmap.insertNode(tc.nodeName, tc.encryptionKey)
		assert.Len(t, cmap.nodeData, tc.count, "Number of nodes in cmap should match with Count")
		assert.True(t, cmap.hasNode(tc.nodeName), "Node name should present in cmap")
		key, ok := cmap.getEncryptionKey(tc.nodeName)
		assert.True(t, ok, "Encryption key for node should be present")
		assert.Equal(t, tc.encryptionKey, key, "Encryption key for node should match")
	}

	// Insert and remove Nodes in CES cache and check for any stale entries present in CES cache.
	for _, tc := range testCases {
		cmap.insertNode(tc.nodeName, tc.encryptionKey)
		cmap.deleteNode(tc.nodeName)
		assert.False(t, cmap.hasNode(tc.nodeName), "Node name is removed from cache, so it shouldn't be in cache")
	}

	assert.Empty(t, cmap.nodeData)
}

func TestCESCacheCIDState(t *testing.T) {
	testCases := []struct {
		name      string
		cid       CID
		gidLabels Labels
		count     int
		gidCount  int
	}{
		{
			name:      "Insert CID - 1",
			cid:       CID("cid1"),
			gidLabels: Labels("test:hello"),
			count:     1,
			gidCount:  1,
		},
		{
			name:      "Insert CID - 2",
			cid:       CID("cid2"),
			gidLabels: Labels("key:value"),
			count:     2,
			gidCount:  2,
		},
		{
			name:      "Insert CID - 3",
			cid:       CID("cid3"),
			gidLabels: Labels("hello:world"),
			count:     3,
			gidCount:  3,
		},
		{
			name:      "Check new CID with duplicate labels",
			cid:       CID("cid4"),
			gidLabels: Labels("key:value"),
			count:     4,
			gidCount:  3,
		},
	}
	cmap := newCESCache()

	// Insert new CEPs in cepCache map and check its total count
	for _, tc := range testCases {
		prevSelectedId, _ := cmap.GetSelectedId(tc.gidLabels)
		cmap.insertCID(tc.cid, tc.gidLabels)
		assert.Len(t, cmap.cidToGidLabels, tc.count, "Number of CIDs in cmap should match with Count")
		assert.Len(t, cmap.globalIdLabelsToCIDSet, tc.gidCount, "Number of GID label entries in cmap should match with Count")
		assert.True(t, cmap.hasCID(tc.cid), "CID should present in cmap")
		assert.False(t, cmap.hasCID("not-really-cid"), "Random string should NOT present in cmap as Key")

		newSelectedId, _ := cmap.GetSelectedId(tc.gidLabels)
		if prevSelectedId == "" {
			assert.Equal(t, newSelectedId, tc.cid, "Newly inserted CID should be selected as the first CID for the GID labels")
		} else {
			assert.Equal(t, newSelectedId, prevSelectedId, "Selected CID should not change if it was already set")
		}
	}

	// Insert and remove CEPs in cepCache and check for any stale entries present in cepCache.
	for _, tc := range testCases {
		cmap.insertCID(tc.cid, tc.gidLabels)
		cmap.deleteCID(tc.cid)
		assert.False(t, cmap.hasCID(tc.cid), "CID should be removed from cache")
	}
	assert.Empty(t, cmap.cidToGidLabels)
	assert.Empty(t, cmap.globalIdLabelsToCIDSet)
}

func TestCESCacheCIDUpdates(t *testing.T) {
	cid1 := CID("cid1")
	labels1 := Labels("key:value")

	cid2 := CID("cid2")

	cmap := newCESCache()

	// Insert first CID
	cmap.insertCID(cid1, labels1)
	selectedId, ok := cmap.GetSelectedId(labels1)
	assert.True(t, ok, "Selected ID should be present for labels1")
	assert.Equal(t, selectedId, cid1, "Selected ID should be cid1")

	// Insert second CID with same labels
	cmap.insertCID(cid2, labels1)
	selectedId, ok = cmap.GetSelectedId(labels1)
	assert.True(t, ok, "Selected ID should be present for labels1")
	assert.Equal(t, selectedId, cid1, "Selected ID should still be cid1")

	// Remove first CID
	cmap.deleteCID(cid1)
	selectedId, ok = cmap.GetSelectedId(labels1)
	assert.True(t, ok, "Selected ID should be present for labels1 after removing cid1")
	assert.Equal(t, selectedId, cid2, "Selected ID should now be cid2")
}

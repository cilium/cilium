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

func TestCESCacheCIDState(t *testing.T) {
	testCases := []struct {
		name      string
		cid       CID
		gidLabels Label
		count     int
		gidCount  int
	}{
		{
			name:      "Insert CID - 1",
			cid:       CID("cid1"),
			gidLabels: Label("test:hello"),
			count:     1,
			gidCount:  1,
		},
		{
			name:      "Insert CID - 2",
			cid:       CID("cid2"),
			gidLabels: Label("key:value"),
			count:     2,
			gidCount:  2,
		},
		{
			name:      "Insert CID - 3",
			cid:       CID("cid3"),
			gidLabels: Label("hello:world"),
			count:     3,
			gidCount:  3,
		},
		{
			name:      "Check new CID with duplicate labels",
			cid:       CID("cid4"),
			gidLabels: Label("key:value"),
			count:     4,
			gidCount:  3,
		},
	}
	cmap := newCESCache()

	// Insert new CEPs in cepCache map and check its total count
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			prevSelectedId, _ := cmap.GetSelectedId(tc.gidLabels)
			cmap.insertCID(CID(tc.cid), Label(tc.gidLabels))
			assert.Equal(t, len(cmap.cidToGidLabels), tc.count, "Number of CIDs in cmap should match with Count")
			assert.Equal(t, len(cmap.globalIdLabelsToCIDSet), tc.gidCount, "Number of GID label entries in cmap should match with Count")
			assert.True(t, cmap.hasCID(tc.cid, tc.gidLabels), "CID should present in cmap")
			assert.False(t, cmap.hasCID("not-really-cid", tc.gidLabels), "Random string should NOT present in cmap as Key")

			newSelectedId, _ := cmap.GetSelectedId(tc.gidLabels)
			if prevSelectedId == "" {
				assert.Equal(t, newSelectedId, tc.cid, "Newly inserted CID should be selected as the first CID for the GID labels")
			} else {
				assert.Equal(t, newSelectedId, prevSelectedId, "Selected CID should not change if it was already set")
			}
		})
	}

	// Insert and remove CEPs in cepCache and check for any stale entries present in cepCache.
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCID(CID(tc.cid), Label(tc.gidLabels))
			cmap.deleteCID(tc.cid, tc.gidLabels)
			assert.False(t, cmap.hasCID(tc.cid, tc.gidLabels), "CID should be removed from cache")
		})
	}
	assert.Empty(t, cmap.cidToGidLabels)
	assert.Empty(t, cmap.globalIdLabelsToCIDSet)
}

func TestCESCacheCESState(t *testing.T) {
	testCases := []struct {
		name    string
		cesName CESName
		ns      string
		count   int
		nsCount int
	}{
		{
			name:    "Insert CES - 1",
			cesName: CESName("ces-dfbkjswert-twis"),
			ns:      "ns",
			count:   1,
			nsCount: 1,
		},
		{
			name:    "Insert CES - 2",
			cesName: CESName("ces-dfbkjswert-rsci"),
			ns:      "ns2",
			count:   2,
			nsCount: 1,
		},
		{
			name:    "Insert CES - 3",
			cesName: CESName("ces-dfbkjswert-fgih"),
			ns:      "ns2",
			count:   3,
			nsCount: 2,
		},
	}
	cmap := newCESCache()

	// Insert new CESs in ces cache and check its total count
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCES(CESName(tc.cesName), tc.ns)
			assert.Equal(t, cmap.getCESCount(), tc.count, "Number of CES entries in cmap should match with Count")
			assert.Len(t, cmap.getCESInNs(tc.ns), tc.nsCount, "Number of CES entries for the given namespace should match with nsCount")
		})
	}

	// Insert and remove CES in cescache and check for any stale entries present in cescache.
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCES(CESName(tc.cesName), tc.ns)
			assert.True(t, cmap.hasCESName(CESName(tc.cesName)), "CES name should be there in map")
			cmap.deleteCES(CESName(tc.cesName))
			assert.False(t, cmap.hasCESName(CESName(tc.cesName)), "CES name is removed from cache, so it shouldn't be in cache")
		})
	}

	assert.Empty(t, cmap.cesData)

	assert.NotEmpty(t, cmap.nsData)
	cmap.deleteNs("ns")
	cmap.deleteNs("ns2")
	assert.Empty(t, cmap.nsData)
}

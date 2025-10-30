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
		cmap.insertCES(tc.cesName, tc.ns)
		assert.Equal(t, cmap.getCESCount(), tc.count, "Number of CES entries in cmap should match with Count")
		assert.Len(t, cmap.getCESInNs(tc.ns), tc.nsCount, "Number of CES entries for the given namespace should match with nsCount")
	}

	// Insert and remove CES in cescache and check for any stale entries present in cescache.
	for _, tc := range testCases {
		cmap.insertCES(tc.cesName, tc.ns)
		assert.True(t, cmap.hasCESName(tc.cesName), "CES name should be there in map")
		cmap.deleteCES(tc.cesName)
		assert.False(t, cmap.hasCESName(tc.cesName), "CES name is removed from cache, so it shouldn't be in cache")
	}

	assert.Empty(t, cmap.cesData)
	assert.Empty(t, cmap.nsData)
}

func TestCESCacheChangeCIDLabels(t *testing.T) {
	// Insert initial CID and labels and validate initial state
	cid1 := CID("cid1")
	labels1 := Labels("key1:value1")
	cmap := newCESCache()
	cmap.insertCID(cid1, labels1)

	assert.True(t, cmap.hasCID(cid1), "CID 'cid1' should be present in cache")
	assert.Equal(t, cmap.cidToGidLabels[cid1], labels1, "CID 'cid1' should map to correct labels")
	assert.Contains(t, cmap.globalIdLabelsToCIDSet[labels1].ids, cid1, "Labels 'key1:value1' should map to CID 'cid1'")
	storedCID, found := cmap.GetSelectedId(labels1)
	assert.True(t, found, "Selected ID for labels 'key1:value1' should be found")
	assert.Equal(t, storedCID, cid1, "Selected ID for labels 'key1:value1' should be 'cid1'")

	// Insert a CEP that uses the CID
	ces1 := CESName("ces1")
	cmap.insertCES(ces1, "ns1")
	node1 := NodeName("node1")
	cmap.insertNode(node1, EncryptionKey(0))
	cep1 := NewCEPName("cep1", "ns1")
	cmap.addCEP(cep1, ces1, node1, labels1)

	// Change CID's labels and validate updated state
	labels2 := Labels("key2:value2")
	cmap.insertCID(cid1, labels2)
	assert.True(t, cmap.hasCID(cid1), "CID 'cid1' should be present in cache after label change")
	assert.Equal(t, cmap.cidToGidLabels[cid1], labels2, "CID 'cid1' should map to updated labels")
	assert.NotContains(t, cmap.globalIdLabelsToCIDSet[labels1].ids, cid1, "Old labels 'key1:value1' should NOT map to CID 'cid1'")
	assert.Contains(t, cmap.globalIdLabelsToCIDSet[labels2].ids, cid1, "New labels 'key2:value2' should map to CID 'cid1'")
	storedCID, found = cmap.GetSelectedId(labels2)
	assert.True(t, found, "Selected ID for new labels 'key2:value2' should be found")
	assert.Equal(t, storedCID, cid1, "Selected ID for new labels 'key2:value2' should be 'cid1'")
	// Old labels have no more CIDs but do have CEPs, so they map to the same selected ID but have no CIDs
	storedCID, found = cmap.GetSelectedId(labels1)
	assert.True(t, found, "Selected ID for old labels 'key1:value1' should still be found")
	assert.Equal(t, storedCID, cid1, "Selected ID for old labels 'key1:value1' should still be 'cid1'")
	assert.Empty(t, cmap.globalIdLabelsToCIDSet[labels1].ids, "Old labels are mapped to no CIDs")
}

func TestCESCacheState(t *testing.T) {
	testCases := []struct {
		name      string
		cepName   CEPName
		cesName   CESName
		nodeName  NodeName
		cid       CID
		gidLabels Labels
		count     int
	}{
		{
			name:      "Insert CEP when CID not created yet",
			cepName:   NewCEPName("cilium-adf8-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node1"),
			cid:       CID(""),
			gidLabels: Labels("test:hello"),
			count:     1,
		},
		{
			name:      "Insert CEPs - 1",
			cepName:   NewCEPName("cilium-adf8-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node1"),
			cid:       CID("cid1"),
			gidLabels: Labels("test:hello"),
			count:     1,
		},
		{
			name:      "Insert CEPs - 2",
			cepName:   NewCEPName("cilium-dtyr-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node2"),
			cid:       CID("cid2"),
			gidLabels: Labels("key:value"),
			count:     2,
		},
		{
			name:      "Insert CEPs - 3",
			cepName:   NewCEPName("cilium-fgh8-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node1"),
			cid:       CID("cid1"),
			gidLabels: Labels("test:hello"),
			count:     3,
		},
		{
			name:      "Insert CEPs - 4",
			cepName:   NewCEPName("cilium-cspn-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node3"),
			cid:       CID("cid2"),
			gidLabels: Labels("key:value"),
			count:     4,
		},
		{
			name:      "Check same CEP-name with CES name",
			cepName:   NewCEPName("cilium-cspn-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-0wis"),
			nodeName:  NodeName("node3"),
			cid:       CID("cid2"),
			gidLabels: Labels("key:value"),
			count:     4,
		},
		{
			name:      "Check CEP with same labels, different CID",
			cepName:   NewCEPName("cilium-asdf-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node3"),
			cid:       CID("cid3"),
			gidLabels: Labels("key:value"),
			count:     5,
		},
	}
	cmap := newCESCache()

	// Insert new CEPs in cepCache map and check its total count
	for _, tc := range testCases {
		prevSelectedId, _ := cmap.GetSelectedId(tc.gidLabels)

		cmap.insertCES(CESName(tc.cesName), "ns")
		// Add CEP if CID is empty, else upsert CEP
		//if tc.cid == "" {
		cmap.addCEP(tc.cepName, tc.cesName, tc.nodeName, tc.gidLabels)
		if tc.cid != "" {
			cmap.insertCID(tc.cid, tc.gidLabels)
		}
		// } else {
		// 	cmap.upsertCEP(tc.cepName, tc.cesName, tc.nodeName, tc.gidLabels, tc.cid)
		// }

		assert.Equal(t, cmap.countCEPs(), tc.count, "Number of CEP entries in cmap should match with Count")
		assert.True(t, cmap.hasCEP(tc.cepName), "CEP name should be present in CES cache")
		assert.False(t, cmap.hasCEP(NewCEPName("not-really-cep", "ns")), "Random string should NOT present in cache as Key")
		assert.True(t, cmap.hasNode(tc.nodeName), "Node name should be present in cache")

		if tc.cid == "" {
			assert.False(t, cmap.hasCID(tc.cid), "CEP with empty CID, so CID should NOT be present in CES cache")
		} else {
			assert.True(t, cmap.hasCID(tc.cid), "CEP with non-empty CID should be present in CES cache")
		}

		newSelectedId, _ := cmap.GetSelectedId(tc.gidLabels)
		if prevSelectedId == "" {
			assert.Equal(t, newSelectedId, tc.cid, "Newly inserted CID should be selected as the first CID for the GID labels")
		} else {
			assert.Equal(t, newSelectedId, prevSelectedId, "Selected CID should not change if it was already set")
		}
	}

	// Insert and remove CEPs in cepCache and check for any stale entries present in cepCache.
	for _, tc := range testCases {
		cmap.insertCES(CESName(tc.cesName), "ns")
		cmap.addCEP(tc.cepName, tc.cesName, tc.nodeName, tc.gidLabels)
		cesName, ok := cmap.getCESName(tc.cepName)
		assert.True(t, ok, "CEP name should be there in map")
		assert.Equal(t, cesName, tc.cesName, "CEP name should match with cesName")
		cmap.deleteCEP(tc.cepName)
		assert.False(t, cmap.hasCEP(tc.cepName), "CEP name is removed from cache, so it shouldn't be in cache")
	}
	assert.Empty(t, cmap.cepData)
	assert.NotEmpty(t, cmap.cesData)
	assert.NotEmpty(t, cmap.nodeData)
	assert.NotEmpty(t, cmap.globalIdLabelsToCIDSet)

	// CEPs removed from all maps
	for ces := range cmap.cesData {
		assert.Empty(t, cmap.cesData[ces].ceps)
	}
	for n := range cmap.nodeData {
		assert.Empty(t, cmap.nodeData[n].ceps)
	}
	for gidLabels := range cmap.globalIdLabelsToCIDSet {
		assert.Empty(t, cmap.globalIdLabelsToCIDSet[gidLabels].ceps)
	}

	// Clean up CES
	cmap.deleteCES(CESName("ces-dfbkjswert-twis"))
	cmap.deleteCES(CESName("ces-dfbkjswert-0wis"))
	assert.Empty(t, cmap.cesData)

	// Clean up CiliumNode
	cmap.deleteNode("node1")
	cmap.deleteNode("node2")
	cmap.deleteNode("node3")
	assert.Empty(t, cmap.nodeData)
}

func TestCESCacheClearsStaleState(t *testing.T) {
	testCases := []struct {
		name      string
		cepName   CEPName
		cesName   CESName
		nodeName  NodeName
		cid       CID
		gidLabels Labels
		count     int
	}{
		{
			name:      "Insert CEPs - 1",
			cepName:   NewCEPName("cilium-adf8-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node1"),
			cid:       CID("cid1"),
			gidLabels: Labels("test:hello"),
			count:     1,
		},
		{
			name:      "Insert CEPs - 2",
			cepName:   NewCEPName("cilium-adf8-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node2"),
			cid:       CID("cid2"),
			gidLabels: Labels("key:value"),
			count:     1,
		},
	}
	cmap := newCESCache()

	// Insert new CEPs in cepCache map and check its total count
	for _, tc := range testCases {
		prevSelectedId, _ := cmap.GetSelectedId(tc.gidLabels)
		var prevNode NodeName
		var prevLabel Labels
		if _, exists := cmap.cepData[tc.cepName]; exists {
			prevNode = cmap.cepData[tc.cepName].node
			prevLabel = cmap.cepData[tc.cepName].labels
		}

		cmap.insertCES(tc.cesName, "ns")
		cmap.addCEP(tc.cepName, tc.cesName, tc.nodeName, tc.gidLabels)
		cmap.insertCID(tc.cid, tc.gidLabels)

		assert.Equal(t, cmap.countCEPs(), tc.count, "Number of CEP entries in cmap should match with Count")
		assert.True(t, cmap.hasCEP(tc.cepName), "CEP name should be present in CES cache")
		assert.True(t, cmap.hasNode(tc.nodeName), "Node name should be present in cache")
		assert.True(t, cmap.hasCID(tc.cid), "CEP with non-empty CID should be present in CES cache")

		newSelectedId, _ := cmap.GetSelectedId(tc.gidLabels)
		// Ensure old state is cleared and new state is set correctly
		if prevSelectedId != "" {
			cid, ok := cmap.getCIDForCEP(tc.cepName)
			assert.True(t, ok, "CEP should have a CID in cache")
			assert.Equal(t, newSelectedId, cid, "CID should be updated to new CID for CEP")
			assert.NotContains(t, cmap.cidToGidLabels, prevSelectedId, "Old selected CID should be removed from cidToGidLabels map")
		}
		if prevLabel != "" {
			assert.Equal(t, tc.gidLabels, cmap.cepData[tc.cepName].labels, "GID labels for CEP should be updated to new labels")
			assert.NotContains(t, cmap.globalIdLabelsToCIDSet[prevLabel].ceps, tc.cepName, "CEP should be removed from previous GID label's CEP list")
		}
		if prevNode != "" {
			assert.Equal(t, tc.nodeName, cmap.cepData[tc.cepName].node, "Node name for CEP should be updated to new node name")
			assert.NotContains(t, cmap.nodeData[prevNode].ceps, tc.cepName, "CEP should be removed from previous node's CEP list")
			assert.True(t, cmap.hasNode(prevNode), "Previous node should still be present in cache")
			assert.True(t, cmap.hasNode(tc.nodeName), "New node should be present in cache")
		}
	}
}

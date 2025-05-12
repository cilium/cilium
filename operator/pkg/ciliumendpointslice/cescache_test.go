// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCepToCESCounts(t *testing.T) {
	testCases := []struct {
		name      string
		cepName   CEPName
		cesName   CESName
		nodeName  NodeName
		cid       CID
		gidLabels string
		count     int
	}{
		{
			name:      "Insert CEPs - 1",
			cepName:   NewCEPName("cilium-adf8-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node1"),
			cid:       CID("cid1"),
			gidLabels: "test:hello",
			count:     1,
		},
		{
			name:      "Insert CEPs - 2",
			cepName:   NewCEPName("cilium-dtyr-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node2"),
			cid:       CID("cid2"),
			gidLabels: "key:value",
			count:     2,
		},
		{
			name:      "Insert CEPs - 3",
			cepName:   NewCEPName("cilium-fgh8-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node1"),
			cid:       CID("cid1"),
			gidLabels: "test:hello",
			count:     3,
		},
		{
			name:      "Insert CEPs - 4",
			cepName:   NewCEPName("cilium-cspn-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-twis"),
			nodeName:  NodeName("node3"),
			cid:       CID("cid2"),
			gidLabels: "key:value",
			count:     4,
		},
		{
			name:      "Check same CEP-name with CES name",
			cepName:   NewCEPName("cilium-cspn-kube-system", "ns"),
			cesName:   CESName("ces-dfbkjswert-0wis"),
			nodeName:  NodeName("node3"),
			cid:       CID("cid2"),
			gidLabels: "key:value",
			count:     4,
		},
	}
	cmap := newCESCache()

	// Insert new CEPs in cepCache map and check its total count
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCES(CESName(tc.cesName), "ns")
			cmap.insertCEP(CEPName(tc.cepName), tc.cesName, tc.nodeName, tc.gidLabels, tc.cid)
			assert.Equal(t, cmap.countCEPs(), tc.count, "Number of CEP entries in cmap should match with Count")
			assert.True(t, cmap.hasCEP(tc.cepName), "CEP name should present in cmap")
			assert.False(t, cmap.hasCEP(NewCEPName("not-really-cep", "ns")), "Random string should NOT present in cmap as Key")
			assert.True(t, cmap.hasNode(tc.nodeName))
			assert.True(t, cmap.hasCID(tc.cid, tc.gidLabels))
		})
	}

	// Insert and remove CEPs in cepCache and check for any stale entries present in cepCache.
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCES(CESName(tc.cesName), "ns")
			cmap.insertCEP(tc.cepName, tc.cesName, tc.nodeName, tc.gidLabels, tc.cid)
			cesName, ok := cmap.getCESName(tc.cepName)
			assert.True(t, ok, "CEP name should be there in map")
			assert.Equal(t, cesName, tc.cesName, "CEP name should match with cesName")
			cmap.deleteCEP(tc.cepName)
			assert.False(t, cmap.hasCEP(tc.cepName), "CEP name is removed from cache, so it shouldn't be in cache")
		})
	}
	assert.Empty(t, cmap.cepNameToData)
	assert.NotEmpty(t, cmap.cesNameToData)
	assert.NotEmpty(t, cmap.nodeNameToData)
	assert.NotEmpty(t, cmap.globalIdLabelsToCIDSet)

	// CEPs removed from all maps
	for ces := range cmap.cesNameToData {
		assert.Empty(t, cmap.cesNameToData[ces].ceps)
	}
	for n := range cmap.nodeNameToData {
		assert.Empty(t, cmap.nodeNameToData[n].ceps)
	}
	for gidLabels := range cmap.globalIdLabelsToCIDSet {
		assert.Empty(t, cmap.globalIdLabelsToCIDSet[gidLabels].ceps)
	}

	// Clean up CES
	cmap.deleteCES(CESName("ces-dfbkjswert-twis"))
	cmap.deleteCES(CESName("ces-dfbkjswert-0wis"))
	assert.Empty(t, cmap.cesNameToData)

	// Clean up CiliumNode
	cmap.deleteNode("node1")
	cmap.deleteNode("node2")
	cmap.deleteNode("node3")
	assert.Empty(t, cmap.nodeNameToData)
}

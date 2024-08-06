// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCepToCESCounts(t *testing.T) {
	testCases := []struct {
		name    string
		cepName CEPName
		cesName CESName
		count   int
	}{
		{
			name:    "Insert CEPs - 1",
			cepName: NewCEPName("cilium-adf8-kube-system", "ns"),
			cesName: CESName("ces-dfbkjswert-twis"),
			count:   1,
		},
		{
			name:    "Insert CEPs - 2",
			cepName: NewCEPName("cilium-dtyr-kube-system", "ns"),
			cesName: CESName("ces-dfbkjswert-twis"),
			count:   2,
		},
		{
			name:    "Insert CEPs - 3",
			cepName: NewCEPName("cilium-fgh8-kube-system", "ns"),
			cesName: CESName("ces-dfbkjswert-twis"),
			count:   3,
		},
		{
			name:    "Insert CEPs - 4",
			cepName: NewCEPName("cilium-cspn-kube-system", "ns"),
			cesName: CESName("ces-dfbkjswert-twis"),
			count:   4,
		},
		{
			name:    "Check same CEP-name with CES name",
			cepName: NewCEPName("cilium-cspn-kube-system", "ns"),
			cesName: CESName("ces-dfbkjswert-0wis"),
			count:   4,
		},
	}
	cmap := newCESToCEPMapping()

	// Insert new CEPs in cepCache map and check its total count
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCES(CESName(tc.cesName), "ns")
			cmap.insertCEP(CEPName(tc.cepName), CESName(tc.cesName))
			assert.Equal(t, cmap.countCEPs(), tc.count, "Number of CEP entries in cmap should match with Count")
			assert.Equal(t, cmap.hasCEP(tc.cepName), true, "CEP name should present in cmap")
			assert.Equal(t, cmap.hasCEP(NewCEPName("not-really-cep", "ns")), false, "Random string should NOT present in cmap as Key")
		})
	}

	// Insert and remove CEPs in cepCache and check for any stale entries present in cepCache.
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCES(CESName(tc.cesName), "ns")
			cmap.insertCEP(tc.cepName, tc.cesName)
			cesName, ok := cmap.getCESName(tc.cepName)
			assert.Equal(t, ok, true, "CEP name should be there in map")
			assert.Equal(t, cesName, tc.cesName, "CEP name should match with cesName")
			cmap.deleteCEP(tc.cepName)
			assert.Equal(t, cmap.hasCEP(tc.cepName), false, "CEP name is removed from cache, so it shouldn't be in cache")
		})
	}

}

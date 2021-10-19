// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !privileged_tests
// +build !privileged_tests

package ciliumendpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCepToCESCounts(t *testing.T) {
	testCases := []struct {
		name    string
		cepName string
		cesName string
		count   int
	}{
		{
			name:    "Insert CEPs - 1",
			cepName: "cilium-adf8-kube-system",
			cesName: "ces-dfbkjswert-twis",
			count:   1,
		},
		{
			name:    "Insert CEPs - 2",
			cepName: "cilium-dtyr-kube-system",
			cesName: "ces-dfbkjswert-twis",
			count:   2,
		},
		{
			name:    "Insert CEPs - 3",
			cepName: "cilium-fgh8-kube-system",
			cesName: "ces-dfbkjswert-twis",
			count:   3,
		},
		{
			name:    "Insert CEPs - 4",
			cepName: "cilium-cspn-kube-system",
			cesName: "ces-dfbkjswert-twis",
			count:   4,
		},
		{
			name:    "Check same CEP-name with CES name",
			cepName: "cilium-cspn-kube-system",
			cesName: "ces-dfbkjswert-0wis",
			count:   4,
		},
	}
	cmap := newDesiredCESMap()

	// Insert new CEPs in cepCache map and check its total count
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCEP(tc.cepName, tc.cesName)
			assert.Equal(t, cmap.countCEPs(), tc.count, "Number of CEP entries in cmap should match with Count")
			assert.Equal(t, cmap.hasCEP(tc.cepName), true, "CEP name should present in cmap")
			assert.Equal(t, cmap.hasCEP(tc.cesName), false, "CES name should NOT present in cmap as Key")
		})
	}

	// Insert and remove CEPs in cepCache and check for any stale entries present in cepCache.
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			cmap.insertCEP(tc.cepName, tc.cesName)
			cesName, ok := cmap.getCESName(tc.cepName)
			assert.Equal(t, ok, true, "CEP name should be there in map")
			assert.Equal(t, cesName, tc.cesName, "CEP name should match with cesName")
			cmap.deleteCEP(tc.cepName)
			assert.Equal(t, cmap.hasCEP(tc.cepName), false, "CEP name is removed from cache, so it shouldn't be in cache")
		})
	}

}

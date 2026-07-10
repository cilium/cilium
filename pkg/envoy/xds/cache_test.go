// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
)

func TestGetResource(t *testing.T) {
	logger := hivetest.Logger(t)
	c := NewCache(logger)
	c.resources[cacheKey{typeURL: "a", resourceName: "a1"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "a", resourceName: "a2"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "b", resourceName: "a1"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "b", resourceName: "b2"}] = cacheValue{lastModifiedVersion: 1}

	for _, tc := range []struct {
		desc            string
		typeURL         string
		version         uint64
		getNames        []string
		wantNames       []string
		wantNilResponse bool
	}{
		{
			desc:      "return resource by name",
			typeURL:   "a",
			getNames:  []string{"a1"},
			wantNames: []string{"a1"},
		},
		{
			desc:      "return all resources for given url",
			typeURL:   "a",
			wantNames: []string{"a1", "a2"},
		},
		{
			desc:      "no resources found for given url",
			typeURL:   "c",
			wantNames: []string{},
		},
		{
			desc:      "no resources found for given name and url",
			typeURL:   "b",
			getNames:  []string{"c1"},
			wantNames: []string{},
		},
		{
			desc:            "resource has no updates",
			typeURL:         "b",
			version:         1,
			getNames:        []string{"b2"},
			wantNilResponse: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Ignore version and nodeID they does not impact GetResource logic.
			// Ignore error since it always returns nil.
			got, _ := c.GetResources(tc.typeURL, tc.version, "", tc.getNames)
			gotNilResponse := got == nil
			if gotNilResponse != tc.wantNilResponse {
				t.Fatalf("Returned response mismatch want: gotNilResponse != tc.wantNilResponse  %v != %v", gotNilResponse, tc.wantNilResponse)
			}
			if got == nil {
				return
			}
			slices.Sort(got.ResourceNames)
			if diff := cmp.Diff(got.ResourceNames, tc.wantNames); diff != "" {
				t.Fatalf("returned resources mismatch (-got/+want): %v", diff)
			}
		})
	}
}

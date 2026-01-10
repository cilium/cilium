// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

func TestGetCIDRPrefixes(t *testing.T) {
	rules := types.PolicyEntries{{
		Subject: types.NewLabelSelectorFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: true,
		L3:      types.ToSelectors(api.CIDR("192.0.2.0/24")),
	}, {
		Subject: types.NewLabelSelectorFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: false,
		L3: types.ToSelectors(api.CIDRSlice{
			"192.0.2.0/24",
			"192.0.3.0/24",
		}...),
	}}

	// We have three CIDR instances in the ruleset, check that all exist
	expectedCIDRStrings := []string{
		"192.0.2.0/24",
		"192.0.3.0/24",
	}
	expectedCIDRs := []netip.Prefix{}
	for _, ipStr := range expectedCIDRStrings {
		cidr := netip.MustParsePrefix(ipStr)
		expectedCIDRs = append(expectedCIDRs, cidr)
	}
	require.ElementsMatch(t, expectedCIDRs, GetCIDRPrefixes(rules))

	// Now, test with CIDRSets.
	rules = types.PolicyEntries{{
		Subject: types.NewLabelSelectorFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: true,
		L3: types.ToSelectors(api.CIDRRule{
			Cidr:        "192.0.2.0/24",
			ExceptCIDRs: []api.CIDR{"192.0.2.128/25"},
		}),
	}, {
		L3: types.ToSelectors(api.CIDRRule{
			Cidr:        "10.0.0.0/8",
			ExceptCIDRs: []api.CIDR{"10.0.0.0/16"},
		}),
	}}

	// Once exceptions apply, here are the list of CIDRs.
	expectedCIDRStrings = []string{
		"192.0.2.0/24",
		"192.0.2.128/25",
		"10.0.0.0/8",
		"10.0.0.0/16",
	}
	expectedCIDRs = []netip.Prefix{}
	for _, ipStr := range expectedCIDRStrings {
		cidr := netip.MustParsePrefix(ipStr)
		expectedCIDRs = append(expectedCIDRs, cidr)
	}
	require.ElementsMatch(t, expectedCIDRs, GetCIDRPrefixes(rules))
}

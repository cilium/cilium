// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

func TestGetAsEndpointSelectors(t *testing.T) {
	world := labels.ParseLabelArray("reserved:world")

	labelWorld := labels.ParseSelectLabel("reserved:world")
	esWorld := NewESFromLabels(labelWorld)

	labelWorldIPv4 := labels.ParseSelectLabel("reserved:world-ipv4")
	esWorldIPv4 := NewESFromLabels(labelWorldIPv4)

	labelWorldIPv6 := labels.ParseSelectLabel("reserved:world-ipv6")
	esWorldIPv6 := NewESFromLabels(labelWorldIPv6)

	labelAllV4, err := labels.IPStringToLabel("0.0.0.0/0")
	require.NoError(t, err)
	v4World := NewESFromLabels(labelAllV4)

	labelAllV6, err := labels.IPStringToLabel("::/0")
	require.NoError(t, err)
	v6World := NewESFromLabels(labelAllV6)

	labelOtherCIDR, err := labels.IPStringToLabel("192.168.128.0/24")
	require.NoError(t, err)
	esOtherCIDR := NewESFromLabels(labelOtherCIDR)

	tt := []struct {
		name              string
		cidrs             CIDRSlice
		expectedSelectors EndpointSelectorSlice
		matchesWorld,
		enableIPv4, enableIPv6 bool
	}{
		{
			name: "ipv4 dualstack",
			cidrs: CIDRSlice{
				"0.0.0.0/0",
			},
			expectedSelectors: EndpointSelectorSlice{
				v4World,
				esWorldIPv4,
			},
			matchesWorld: false,
			enableIPv4:   true,
			enableIPv6:   true,
		},
		{
			name: "ipv6 dualstack",
			cidrs: CIDRSlice{
				"::/0",
			},
			expectedSelectors: EndpointSelectorSlice{
				v6World,
				esWorldIPv6,
			},
			matchesWorld: false,
			enableIPv4:   true,
			enableIPv6:   true,
		},
		{
			name: "ipv4 and ipv6 dualstack",
			cidrs: CIDRSlice{
				"0.0.0.0/0",
				"::/0",
				"192.168.128.10/24",
			},
			expectedSelectors: EndpointSelectorSlice{
				v4World,
				v6World,
				esOtherCIDR,
				esWorld,
				esWorldIPv4,
				esWorldIPv6,
			},
			matchesWorld: true,
			enableIPv4:   true,
			enableIPv6:   true,
		},
		{
			name: "ipv4 in ipv4 only",
			cidrs: CIDRSlice{
				"0.0.0.0/0",
			},
			expectedSelectors: EndpointSelectorSlice{
				v4World,
				esWorld,
			},
			matchesWorld: true,
			enableIPv4:   true,
			enableIPv6:   false,
		},
		{
			name: "ipv6 in ipv4 only",
			cidrs: CIDRSlice{
				"::/0",
			},
			expectedSelectors: EndpointSelectorSlice{
				v6World,
			},
			matchesWorld: false,
			enableIPv4:   true,
			enableIPv6:   false,
		},
		{
			name: "ipv4 in ipv6 only",
			cidrs: CIDRSlice{
				"0.0.0.0/0",
			},
			expectedSelectors: EndpointSelectorSlice{
				v4World,
			},
			matchesWorld: false,
			enableIPv4:   false,
			enableIPv6:   true,
		},
		{
			name: "ipv6 in ipv6 only",
			cidrs: CIDRSlice{
				"::/0",
			},
			expectedSelectors: EndpointSelectorSlice{
				v6World,
				esWorld,
			},
			matchesWorld: true,
			enableIPv4:   false,
			enableIPv6:   true,
		},
	}

	for _, test := range tt {
		t.Logf("running test %s:", test.name)
		option.Config.EnableIPv6 = test.enableIPv6
		option.Config.EnableIPv4 = test.enableIPv4
		result := test.cidrs.GetAsEndpointSelectors()
		require.Equal(t, test.matchesWorld, result.Matches(world))
		require.EqualValues(t, test.expectedSelectors, result)
	}
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
}

const CIDRRegex = `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$|^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`

func TestCIDRRegex(t *testing.T) {
	reg := regexp.MustCompile(CIDRRegex)

	goodCIDRs := []string{
		"192.0.2.3/32",
		"192.0.2.0/24",
		"0.0.0.0/0",
		"::/0",
		"::cafe/128",
		"::f00d:cafe/128",
		"0:0:0:0:0:0:0:cafe/128",
		"cafe:cafe:cafe:cafe:cafe:cafe:cafe:cafe/128",
		"bad:f00d:cafe:0:0:0:0:add/64",
		"bad:f00d:cafe::bad/64",
		"f00d::/64",
		"f00d::0:0/120",
		"f00d:cafe::1:2/120",
	}

continueTest:
	for _, input := range goodCIDRs {
		if matched := reg.MatchString(input); matched {
			continue continueTest
		}
		// The below is always false, valid CIDR prefixes should
		// always skip this by continuing in the above loop.
		require.Equal(t, "failed to match CIDR.OneOf[*].Pattern", input)
	}

	badCIDRs := []string{
		"192.0.2.3",
		"192.0.2.3/",
		"abcdef",
		"0.0.0.0/0/0",
		"::",
		":",
		":/",
		"0:0",
		"::cafe/128/12",
		"abc:def",
		"abc:def/64",
		"f00d::/",
		"f00d::0:0",
		"bad.f00d.cafe.0.0.0.0.add/20",
		"::192.0.2.3/128",
		"::ffff:192.0.2.3/128",
		"abcd:192.0.2.3/128",
		":abcd:192.0.2.3/128",
		"abcd::192.0.2.3/128",
		":abcd::192.0.2.3/128",
		"bad::f00d::cafe/1",
		":bad::f00d::cafe/1",
		"::bad::f00d::cafe/1",
		"::bad::food::cafe/1",
	}

	for _, input := range badCIDRs {
		if matched := reg.MatchString(input); matched {
			// The below is always false, invalid CIDR
			// prefixes are not supposed to match the regex.
			require.Equal(t, "unexpectedly matched CIDR.OneOf[*].Pattern", input)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"math/rand"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
)

func TestGetCIDRLabels(t *testing.T) {
	// clear the cache
	cidrLabelsCache, _ = simplelru.NewLRU[netip.Prefix, []Label](cidrLabelsCacheMaxSize, nil)

	// save global config and restore it at the end of the test
	enableIPv4, enableIPv6 := option.Config.EnableIPv4, option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4, option.Config.EnableIPv6 = enableIPv4, enableIPv6
	})

	for _, tc := range []struct {
		name       string
		enableIPv4 bool
		enableIPv6 bool
		prefix     netip.Prefix
		expected   LabelArray
	}{
		{
			name:       "IPv4 /32 prefix",
			enableIPv4: true,
			enableIPv6: false,
			prefix:     netip.MustParsePrefix("192.0.2.3/32"),
			expected: ParseLabelArray(
				"cidr:0.0.0.0/0",
				"cidr:128.0.0.0/1", "cidr:192.0.0.0/2", "cidr:192.0.0.0/3", "cidr:192.0.0.0/4",
				"cidr:192.0.0.0/5", "cidr:192.0.0.0/6", "cidr:192.0.0.0/7", "cidr:192.0.0.0/8",
				"cidr:192.0.0.0/9", "cidr:192.0.0.0/10", "cidr:192.0.0.0/11", "cidr:192.0.0.0/12",
				"cidr:192.0.0.0/13", "cidr:192.0.0.0/14", "cidr:192.0.0.0/15", "cidr:192.0.0.0/16",
				"cidr:192.0.0.0/17", "cidr:192.0.0.0/18", "cidr:192.0.0.0/19", "cidr:192.0.0.0/20",
				"cidr:192.0.0.0/21", "cidr:192.0.0.0/22", "cidr:192.0.2.0/23", "cidr:192.0.2.0/24",
				"cidr:192.0.2.0/25", "cidr:192.0.2.0/26", "cidr:192.0.2.0/27", "cidr:192.0.2.0/28",
				"cidr:192.0.2.0/29", "cidr:192.0.2.0/30", "cidr:192.0.2.2/31", "cidr:192.0.2.3/32",
				"reserved:world",
			),
		},
		{
			name:       "IPv4 /24 prefix",
			enableIPv4: true,
			enableIPv6: false,
			prefix:     netip.MustParsePrefix("192.0.2.0/24"),
			expected: ParseLabelArray(
				"cidr:0.0.0.0/0",
				"cidr:128.0.0.0/1", "cidr:192.0.0.0/2", "cidr:192.0.0.0/3", "cidr:192.0.0.0/4",
				"cidr:192.0.0.0/5", "cidr:192.0.0.0/6", "cidr:192.0.0.0/7", "cidr:192.0.0.0/8",
				"cidr:192.0.0.0/9", "cidr:192.0.0.0/10", "cidr:192.0.0.0/11", "cidr:192.0.0.0/12",
				"cidr:192.0.0.0/13", "cidr:192.0.0.0/14", "cidr:192.0.0.0/15", "cidr:192.0.0.0/16",
				"cidr:192.0.0.0/17", "cidr:192.0.0.0/18", "cidr:192.0.0.0/19", "cidr:192.0.0.0/20",
				"cidr:192.0.0.0/21", "cidr:192.0.0.0/22", "cidr:192.0.2.0/23", "cidr:192.0.2.0/24",
				"reserved:world",
			),
		},
		{
			name:       "IPv4 /16 prefix",
			enableIPv4: true,
			enableIPv6: false,
			prefix:     netip.MustParsePrefix("10.0.0.0/16"),
			expected: ParseLabelArray(
				"cidr:0.0.0.0/0",
				"cidr:0.0.0.0/1", "cidr:0.0.0.0/2", "cidr:0.0.0.0/3", "cidr:0.0.0.0/4",
				"cidr:8.0.0.0/5", "cidr:8.0.0.0/6", "cidr:10.0.0.0/7", "cidr:10.0.0.0/8",
				"cidr:10.0.0.0/9", "cidr:10.0.0.0/10", "cidr:10.0.0.0/11", "cidr:10.0.0.0/12",
				"cidr:10.0.0.0/13", "cidr:10.0.0.0/14", "cidr:10.0.0.0/15", "cidr:10.0.0.0/16",
				"reserved:world",
			),
		},
		{
			name:       "IPv4 zero length prefix",
			enableIPv4: true,
			enableIPv6: false,
			prefix:     netip.MustParsePrefix("0.0.0.0/0"),
			expected: ParseLabelArray(
				"reserved:world",
			),
		},
		{
			name:       "IPv6 /112 prefix",
			enableIPv4: false,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("2001:db8:cafe::cab:4:b0b:0/112"),
			expected: ParseLabelArray(
				// Note that we convert the colons in IPv6 addresses into dashes when
				// translating into labels, because endpointSelectors don't support
				// colons.
				"cidr:0--0/0",
				"cidr:0--0/1", "cidr:0--0/2", "cidr:2000--0/3", "cidr:2000--0/4",
				"cidr:2000--0/5", "cidr:2000--0/6", "cidr:2000--0/7", "cidr:2000--0/8",
				"cidr:2000--0/9", "cidr:2000--0/10", "cidr:2000--0/11", "cidr:2000--0/12",
				"cidr:2000--0/13", "cidr:2000--0/14", "cidr:2000--0/15", "cidr:2001--0/16",
				"cidr:2001--0/17", "cidr:2001--0/18", "cidr:2001--0/19", "cidr:2001--0/20",
				"cidr:2001-800--0/21", "cidr:2001-c00--0/22", "cidr:2001-c00--0/23", "cidr:2001-d00--0/24",
				"cidr:2001-d80--0/25", "cidr:2001-d80--0/26", "cidr:2001-da0--0/27", "cidr:2001-db0--0/28",
				"cidr:2001-db8--0/29", "cidr:2001-db8--0/30", "cidr:2001-db8--0/31", "cidr:2001-db8--0/32",
				"cidr:2001-db8-8000--0/33", "cidr:2001-db8-c000--0/34", "cidr:2001-db8-c000--0/35", "cidr:2001-db8-c000--0/36",
				"cidr:2001-db8-c800--0/37", "cidr:2001-db8-c800--0/38", "cidr:2001-db8-ca00--0/39", "cidr:2001-db8-ca00--0/40",
				"cidr:2001-db8-ca80--0/41", "cidr:2001-db8-cac0--0/42", "cidr:2001-db8-cae0--0/43", "cidr:2001-db8-caf0--0/44",
				"cidr:2001-db8-caf8--0/45", "cidr:2001-db8-cafc--0/46", "cidr:2001-db8-cafe--0/47", "cidr:2001-db8-cafe--0/48",
				"cidr:2001-db8-cafe--0/49", "cidr:2001-db8-cafe--0/50", "cidr:2001-db8-cafe--0/51", "cidr:2001-db8-cafe--0/52",
				"cidr:2001-db8-cafe--0/53", "cidr:2001-db8-cafe--0/54", "cidr:2001-db8-cafe--0/55", "cidr:2001-db8-cafe--0/56",
				"cidr:2001-db8-cafe--0/57", "cidr:2001-db8-cafe--0/58", "cidr:2001-db8-cafe--0/59", "cidr:2001-db8-cafe--0/60",
				"cidr:2001-db8-cafe--0/61", "cidr:2001-db8-cafe--0/62", "cidr:2001-db8-cafe--0/63", "cidr:2001-db8-cafe--0/64",
				"cidr:2001-db8-cafe--0/65", "cidr:2001-db8-cafe--0/66", "cidr:2001-db8-cafe--0/67", "cidr:2001-db8-cafe--0/68",
				"cidr:2001-db8-cafe-0-800--0/69", "cidr:2001-db8-cafe-0-c00--0/70", "cidr:2001-db8-cafe-0-c00--0/71", "cidr:2001-db8-cafe-0-c00--0/72",
				"cidr:2001-db8-cafe-0-c80--0/73", "cidr:2001-db8-cafe-0-c80--0/74", "cidr:2001-db8-cafe-0-ca0--0/75", "cidr:2001-db8-cafe-0-ca0--0/76",
				"cidr:2001-db8-cafe-0-ca8--0/77", "cidr:2001-db8-cafe-0-ca8--0/78", "cidr:2001-db8-cafe-0-caa--0/79", "cidr:2001-db8-cafe-0-cab--0/80",
				"cidr:2001-db8-cafe-0-cab--0/81", "cidr:2001-db8-cafe-0-cab--0/82", "cidr:2001-db8-cafe-0-cab--0/83", "cidr:2001-db8-cafe-0-cab--0/84",
				"cidr:2001-db8-cafe-0-cab--0/85", "cidr:2001-db8-cafe-0-cab--0/86", "cidr:2001-db8-cafe-0-cab--0/87", "cidr:2001-db8-cafe-0-cab--0/88",
				"cidr:2001-db8-cafe-0-cab--0/89", "cidr:2001-db8-cafe-0-cab--0/90", "cidr:2001-db8-cafe-0-cab--0/91", "cidr:2001-db8-cafe-0-cab--0/92",
				"cidr:2001-db8-cafe-0-cab--0/93", "cidr:2001-db8-cafe-0-cab-4--0/94", "cidr:2001-db8-cafe-0-cab-4--0/95", "cidr:2001-db8-cafe-0-cab-4--0/96",
				"cidr:2001-db8-cafe-0-cab-4--0/97", "cidr:2001-db8-cafe-0-cab-4--0/98", "cidr:2001-db8-cafe-0-cab-4--0/99", "cidr:2001-db8-cafe-0-cab-4--0/100",
				"cidr:2001-db8-cafe-0-cab-4-800-0/101", "cidr:2001-db8-cafe-0-cab-4-800-0/102", "cidr:2001-db8-cafe-0-cab-4-a00-0/103", "cidr:2001-db8-cafe-0-cab-4-b00-0/104",
				"cidr:2001-db8-cafe-0-cab-4-b00-0/105", "cidr:2001-db8-cafe-0-cab-4-b00-0/106", "cidr:2001-db8-cafe-0-cab-4-b00-0/107", "cidr:2001-db8-cafe-0-cab-4-b00-0/108",
				"cidr:2001-db8-cafe-0-cab-4-b08-0/109", "cidr:2001-db8-cafe-0-cab-4-b08-0/110", "cidr:2001-db8-cafe-0-cab-4-b0a-0/111", "cidr:2001-db8-cafe-0-cab-4-b0b-0/112",
				"reserved:world",
			),
		},
		{
			name:       "IPv6 /128 prefix",
			enableIPv4: false,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("2001:DB8::1/128"),
			expected: ParseLabelArray(
				"cidr:0--0/0",
				"cidr:0--0/1", "cidr:0--0/2", "cidr:2000--0/3", "cidr:2000--0/4",
				"cidr:2000--0/5", "cidr:2000--0/6", "cidr:2000--0/7", "cidr:2000--0/8",
				"cidr:2000--0/9", "cidr:2000--0/10", "cidr:2000--0/11", "cidr:2000--0/12",
				"cidr:2000--0/13", "cidr:2000--0/14", "cidr:2000--0/15", "cidr:2001--0/16",
				"cidr:2001--0/17", "cidr:2001--0/18", "cidr:2001--0/19", "cidr:2001--0/20",
				"cidr:2001-800--0/21", "cidr:2001-c00--0/22", "cidr:2001-c00--0/23", "cidr:2001-d00--0/24",
				"cidr:2001-d80--0/25", "cidr:2001-d80--0/26", "cidr:2001-da0--0/27", "cidr:2001-db0--0/28",
				"cidr:2001-db8--0/29", "cidr:2001-db8--0/30", "cidr:2001-db8--0/31", "cidr:2001-db8--0/32",
				"cidr:2001-db8--0/33", "cidr:2001-db8--0/34", "cidr:2001-db8--0/35", "cidr:2001-db8--0/36",
				"cidr:2001-db8--0/37", "cidr:2001-db8--0/38", "cidr:2001-db8--0/39", "cidr:2001-db8--0/40",
				"cidr:2001-db8--0/41", "cidr:2001-db8--0/42", "cidr:2001-db8--0/43", "cidr:2001-db8--0/44",
				"cidr:2001-db8--0/45", "cidr:2001-db8--0/46", "cidr:2001-db8--0/47", "cidr:2001-db8--0/48",
				"cidr:2001-db8--0/49", "cidr:2001-db8--0/50", "cidr:2001-db8--0/51", "cidr:2001-db8--0/52",
				"cidr:2001-db8--0/53", "cidr:2001-db8--0/54", "cidr:2001-db8--0/55", "cidr:2001-db8--0/56",
				"cidr:2001-db8--0/57", "cidr:2001-db8--0/58", "cidr:2001-db8--0/59", "cidr:2001-db8--0/60",
				"cidr:2001-db8--0/61", "cidr:2001-db8--0/62", "cidr:2001-db8--0/63", "cidr:2001-db8--0/64",
				"cidr:2001-db8--0/65", "cidr:2001-db8--0/66", "cidr:2001-db8--0/67", "cidr:2001-db8--0/68",
				"cidr:2001-db8--0/69", "cidr:2001-db8--0/70", "cidr:2001-db8--0/71", "cidr:2001-db8--0/72",
				"cidr:2001-db8--0/73", "cidr:2001-db8--0/74", "cidr:2001-db8--0/75", "cidr:2001-db8--0/76",
				"cidr:2001-db8--0/77", "cidr:2001-db8--0/78", "cidr:2001-db8--0/79", "cidr:2001-db8--0/80",
				"cidr:2001-db8--0/81", "cidr:2001-db8--0/82", "cidr:2001-db8--0/83", "cidr:2001-db8--0/84",
				"cidr:2001-db8--0/85", "cidr:2001-db8--0/86", "cidr:2001-db8--0/87", "cidr:2001-db8--0/88",
				"cidr:2001-db8--0/89", "cidr:2001-db8--0/90", "cidr:2001-db8--0/91", "cidr:2001-db8--0/92",
				"cidr:2001-db8--0/93", "cidr:2001-db8--0/94", "cidr:2001-db8--0/95", "cidr:2001-db8--0/96",
				"cidr:2001-db8--0/97", "cidr:2001-db8--0/98", "cidr:2001-db8--0/99", "cidr:2001-db8--0/100",
				"cidr:2001-db8--0/101", "cidr:2001-db8--0/102", "cidr:2001-db8--0/103", "cidr:2001-db8--0/104",
				"cidr:2001-db8--0/105", "cidr:2001-db8--0/106", "cidr:2001-db8--0/107", "cidr:2001-db8--0/108",
				"cidr:2001-db8--0/109", "cidr:2001-db8--0/110", "cidr:2001-db8--0/111", "cidr:2001-db8--0/112",
				"cidr:2001-db8--0/113", "cidr:2001-db8--0/114", "cidr:2001-db8--0/115", "cidr:2001-db8--0/116",
				"cidr:2001-db8--0/117", "cidr:2001-db8--0/118", "cidr:2001-db8--0/119", "cidr:2001-db8--0/120",
				"cidr:2001-db8--0/121", "cidr:2001-db8--0/122", "cidr:2001-db8--0/123", "cidr:2001-db8--0/124",
				"cidr:2001-db8--0/125", "cidr:2001-db8--0/126", "cidr:2001-db8--0/127", "cidr:2001-db8--1/128",
				"reserved:world",
			),
		},
		{
			name:       "IPv4 /32 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("192.0.2.3/32"),
			expected: ParseLabelArray(
				"cidr:0.0.0.0/0",
				"cidr:128.0.0.0/1", "cidr:192.0.0.0/2", "cidr:192.0.0.0/3", "cidr:192.0.0.0/4",
				"cidr:192.0.0.0/5", "cidr:192.0.0.0/6", "cidr:192.0.0.0/7", "cidr:192.0.0.0/8",
				"cidr:192.0.0.0/9", "cidr:192.0.0.0/10", "cidr:192.0.0.0/11", "cidr:192.0.0.0/12",
				"cidr:192.0.0.0/13", "cidr:192.0.0.0/14", "cidr:192.0.0.0/15", "cidr:192.0.0.0/16",
				"cidr:192.0.0.0/17", "cidr:192.0.0.0/18", "cidr:192.0.0.0/19", "cidr:192.0.0.0/20",
				"cidr:192.0.0.0/21", "cidr:192.0.0.0/22", "cidr:192.0.2.0/23", "cidr:192.0.2.0/24",
				"cidr:192.0.2.0/25", "cidr:192.0.2.0/26", "cidr:192.0.2.0/27", "cidr:192.0.2.0/28",
				"cidr:192.0.2.0/29", "cidr:192.0.2.0/30", "cidr:192.0.2.2/31", "cidr:192.0.2.3/32",
				"reserved:world-ipv4",
			),
		},
		{
			name:       "IPv4 /24 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("192.0.2.0/24"),
			expected: ParseLabelArray(
				"cidr:0.0.0.0/0",
				"cidr:128.0.0.0/1", "cidr:192.0.0.0/2", "cidr:192.0.0.0/3", "cidr:192.0.0.0/4",
				"cidr:192.0.0.0/5", "cidr:192.0.0.0/6", "cidr:192.0.0.0/7", "cidr:192.0.0.0/8",
				"cidr:192.0.0.0/9", "cidr:192.0.0.0/10", "cidr:192.0.0.0/11", "cidr:192.0.0.0/12",
				"cidr:192.0.0.0/13", "cidr:192.0.0.0/14", "cidr:192.0.0.0/15", "cidr:192.0.0.0/16",
				"cidr:192.0.0.0/17", "cidr:192.0.0.0/18", "cidr:192.0.0.0/19", "cidr:192.0.0.0/20",
				"cidr:192.0.0.0/21", "cidr:192.0.0.0/22", "cidr:192.0.2.0/23", "cidr:192.0.2.0/24",
				"reserved:world-ipv4",
			),
		},
		{
			name:       "IPv4 /16 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("10.0.0.0/16"),
			expected: ParseLabelArray(
				"cidr:0.0.0.0/0",
				"cidr:0.0.0.0/1", "cidr:0.0.0.0/2", "cidr:0.0.0.0/3", "cidr:0.0.0.0/4",
				"cidr:8.0.0.0/5", "cidr:8.0.0.0/6", "cidr:10.0.0.0/7", "cidr:10.0.0.0/8",
				"cidr:10.0.0.0/9", "cidr:10.0.0.0/10", "cidr:10.0.0.0/11", "cidr:10.0.0.0/12",
				"cidr:10.0.0.0/13", "cidr:10.0.0.0/14", "cidr:10.0.0.0/15", "cidr:10.0.0.0/16",
				"reserved:world-ipv4",
			),
		},
		{
			name:       "IPv4 zero length prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("0.0.0.0/0"),
			expected: ParseLabelArray(
				"reserved:world-ipv4",
			),
		},
		{
			name:       "IPv6 /112 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("2001:db8:cafe::cab:4:b0b:0/112"),
			expected: ParseLabelArray(
				"cidr:0--0/0",
				"cidr:0--0/1", "cidr:0--0/2", "cidr:2000--0/3", "cidr:2000--0/4",
				"cidr:2000--0/5", "cidr:2000--0/6", "cidr:2000--0/7", "cidr:2000--0/8",
				"cidr:2000--0/9", "cidr:2000--0/10", "cidr:2000--0/11", "cidr:2000--0/12",
				"cidr:2000--0/13", "cidr:2000--0/14", "cidr:2000--0/15", "cidr:2001--0/16",
				"cidr:2001--0/17", "cidr:2001--0/18", "cidr:2001--0/19", "cidr:2001--0/20",
				"cidr:2001-800--0/21", "cidr:2001-c00--0/22", "cidr:2001-c00--0/23", "cidr:2001-d00--0/24",
				"cidr:2001-d80--0/25", "cidr:2001-d80--0/26", "cidr:2001-da0--0/27", "cidr:2001-db0--0/28",
				"cidr:2001-db8--0/29", "cidr:2001-db8--0/30", "cidr:2001-db8--0/31", "cidr:2001-db8--0/32",
				"cidr:2001-db8-8000--0/33", "cidr:2001-db8-c000--0/34", "cidr:2001-db8-c000--0/35", "cidr:2001-db8-c000--0/36",
				"cidr:2001-db8-c800--0/37", "cidr:2001-db8-c800--0/38", "cidr:2001-db8-ca00--0/39", "cidr:2001-db8-ca00--0/40",
				"cidr:2001-db8-ca80--0/41", "cidr:2001-db8-cac0--0/42", "cidr:2001-db8-cae0--0/43", "cidr:2001-db8-caf0--0/44",
				"cidr:2001-db8-caf8--0/45", "cidr:2001-db8-cafc--0/46", "cidr:2001-db8-cafe--0/47", "cidr:2001-db8-cafe--0/48",
				"cidr:2001-db8-cafe--0/49", "cidr:2001-db8-cafe--0/50", "cidr:2001-db8-cafe--0/51", "cidr:2001-db8-cafe--0/52",
				"cidr:2001-db8-cafe--0/53", "cidr:2001-db8-cafe--0/54", "cidr:2001-db8-cafe--0/55", "cidr:2001-db8-cafe--0/56",
				"cidr:2001-db8-cafe--0/57", "cidr:2001-db8-cafe--0/58", "cidr:2001-db8-cafe--0/59", "cidr:2001-db8-cafe--0/60",
				"cidr:2001-db8-cafe--0/61", "cidr:2001-db8-cafe--0/62", "cidr:2001-db8-cafe--0/63", "cidr:2001-db8-cafe--0/64",
				"cidr:2001-db8-cafe--0/65", "cidr:2001-db8-cafe--0/66", "cidr:2001-db8-cafe--0/67", "cidr:2001-db8-cafe--0/68",
				"cidr:2001-db8-cafe-0-800--0/69", "cidr:2001-db8-cafe-0-c00--0/70", "cidr:2001-db8-cafe-0-c00--0/71", "cidr:2001-db8-cafe-0-c00--0/72",
				"cidr:2001-db8-cafe-0-c80--0/73", "cidr:2001-db8-cafe-0-c80--0/74", "cidr:2001-db8-cafe-0-ca0--0/75", "cidr:2001-db8-cafe-0-ca0--0/76",
				"cidr:2001-db8-cafe-0-ca8--0/77", "cidr:2001-db8-cafe-0-ca8--0/78", "cidr:2001-db8-cafe-0-caa--0/79", "cidr:2001-db8-cafe-0-cab--0/80",
				"cidr:2001-db8-cafe-0-cab--0/81", "cidr:2001-db8-cafe-0-cab--0/82", "cidr:2001-db8-cafe-0-cab--0/83", "cidr:2001-db8-cafe-0-cab--0/84",
				"cidr:2001-db8-cafe-0-cab--0/85", "cidr:2001-db8-cafe-0-cab--0/86", "cidr:2001-db8-cafe-0-cab--0/87", "cidr:2001-db8-cafe-0-cab--0/88",
				"cidr:2001-db8-cafe-0-cab--0/89", "cidr:2001-db8-cafe-0-cab--0/90", "cidr:2001-db8-cafe-0-cab--0/91", "cidr:2001-db8-cafe-0-cab--0/92",
				"cidr:2001-db8-cafe-0-cab--0/93", "cidr:2001-db8-cafe-0-cab-4--0/94", "cidr:2001-db8-cafe-0-cab-4--0/95", "cidr:2001-db8-cafe-0-cab-4--0/96",
				"cidr:2001-db8-cafe-0-cab-4--0/97", "cidr:2001-db8-cafe-0-cab-4--0/98", "cidr:2001-db8-cafe-0-cab-4--0/99", "cidr:2001-db8-cafe-0-cab-4--0/100",
				"cidr:2001-db8-cafe-0-cab-4-800-0/101", "cidr:2001-db8-cafe-0-cab-4-800-0/102", "cidr:2001-db8-cafe-0-cab-4-a00-0/103", "cidr:2001-db8-cafe-0-cab-4-b00-0/104",
				"cidr:2001-db8-cafe-0-cab-4-b00-0/105", "cidr:2001-db8-cafe-0-cab-4-b00-0/106", "cidr:2001-db8-cafe-0-cab-4-b00-0/107", "cidr:2001-db8-cafe-0-cab-4-b00-0/108",
				"cidr:2001-db8-cafe-0-cab-4-b08-0/109", "cidr:2001-db8-cafe-0-cab-4-b08-0/110", "cidr:2001-db8-cafe-0-cab-4-b0a-0/111", "cidr:2001-db8-cafe-0-cab-4-b0b-0/112",
				"reserved:world-ipv6",
			),
		},
		{
			name:       "IPv6 /128 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("2001:DB8::1/128"),
			expected: ParseLabelArray(
				"cidr:0--0/0",
				"cidr:0--0/1", "cidr:0--0/2", "cidr:2000--0/3", "cidr:2000--0/4",
				"cidr:2000--0/5", "cidr:2000--0/6", "cidr:2000--0/7", "cidr:2000--0/8",
				"cidr:2000--0/9", "cidr:2000--0/10", "cidr:2000--0/11", "cidr:2000--0/12",
				"cidr:2000--0/13", "cidr:2000--0/14", "cidr:2000--0/15", "cidr:2001--0/16",
				"cidr:2001--0/17", "cidr:2001--0/18", "cidr:2001--0/19", "cidr:2001--0/20",
				"cidr:2001-800--0/21", "cidr:2001-c00--0/22", "cidr:2001-c00--0/23", "cidr:2001-d00--0/24",
				"cidr:2001-d80--0/25", "cidr:2001-d80--0/26", "cidr:2001-da0--0/27", "cidr:2001-db0--0/28",
				"cidr:2001-db8--0/29", "cidr:2001-db8--0/30", "cidr:2001-db8--0/31", "cidr:2001-db8--0/32",
				"cidr:2001-db8--0/33", "cidr:2001-db8--0/34", "cidr:2001-db8--0/35", "cidr:2001-db8--0/36",
				"cidr:2001-db8--0/37", "cidr:2001-db8--0/38", "cidr:2001-db8--0/39", "cidr:2001-db8--0/40",
				"cidr:2001-db8--0/41", "cidr:2001-db8--0/42", "cidr:2001-db8--0/43", "cidr:2001-db8--0/44",
				"cidr:2001-db8--0/45", "cidr:2001-db8--0/46", "cidr:2001-db8--0/47", "cidr:2001-db8--0/48",
				"cidr:2001-db8--0/49", "cidr:2001-db8--0/50", "cidr:2001-db8--0/51", "cidr:2001-db8--0/52",
				"cidr:2001-db8--0/53", "cidr:2001-db8--0/54", "cidr:2001-db8--0/55", "cidr:2001-db8--0/56",
				"cidr:2001-db8--0/57", "cidr:2001-db8--0/58", "cidr:2001-db8--0/59", "cidr:2001-db8--0/60",
				"cidr:2001-db8--0/61", "cidr:2001-db8--0/62", "cidr:2001-db8--0/63", "cidr:2001-db8--0/64",
				"cidr:2001-db8--0/65", "cidr:2001-db8--0/66", "cidr:2001-db8--0/67", "cidr:2001-db8--0/68",
				"cidr:2001-db8--0/69", "cidr:2001-db8--0/70", "cidr:2001-db8--0/71", "cidr:2001-db8--0/72",
				"cidr:2001-db8--0/73", "cidr:2001-db8--0/74", "cidr:2001-db8--0/75", "cidr:2001-db8--0/76",
				"cidr:2001-db8--0/77", "cidr:2001-db8--0/78", "cidr:2001-db8--0/79", "cidr:2001-db8--0/80",
				"cidr:2001-db8--0/81", "cidr:2001-db8--0/82", "cidr:2001-db8--0/83", "cidr:2001-db8--0/84",
				"cidr:2001-db8--0/85", "cidr:2001-db8--0/86", "cidr:2001-db8--0/87", "cidr:2001-db8--0/88",
				"cidr:2001-db8--0/89", "cidr:2001-db8--0/90", "cidr:2001-db8--0/91", "cidr:2001-db8--0/92",
				"cidr:2001-db8--0/93", "cidr:2001-db8--0/94", "cidr:2001-db8--0/95", "cidr:2001-db8--0/96",
				"cidr:2001-db8--0/97", "cidr:2001-db8--0/98", "cidr:2001-db8--0/99", "cidr:2001-db8--0/100",
				"cidr:2001-db8--0/101", "cidr:2001-db8--0/102", "cidr:2001-db8--0/103", "cidr:2001-db8--0/104",
				"cidr:2001-db8--0/105", "cidr:2001-db8--0/106", "cidr:2001-db8--0/107", "cidr:2001-db8--0/108",
				"cidr:2001-db8--0/109", "cidr:2001-db8--0/110", "cidr:2001-db8--0/111", "cidr:2001-db8--0/112",
				"cidr:2001-db8--0/113", "cidr:2001-db8--0/114", "cidr:2001-db8--0/115", "cidr:2001-db8--0/116",
				"cidr:2001-db8--0/117", "cidr:2001-db8--0/118", "cidr:2001-db8--0/119", "cidr:2001-db8--0/120",
				"cidr:2001-db8--0/121", "cidr:2001-db8--0/122", "cidr:2001-db8--0/123", "cidr:2001-db8--0/124",
				"cidr:2001-db8--0/125", "cidr:2001-db8--0/126", "cidr:2001-db8--0/127", "cidr:2001-db8--1/128",
				"reserved:world-ipv6",
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			option.Config.EnableIPv4 = tc.enableIPv4
			option.Config.EnableIPv6 = tc.enableIPv6

			lbls := GetCIDRLabels(tc.prefix)
			lblArray := lbls.LabelArray()
			assert.ElementsMatch(t, lblArray, tc.expected)

			// compute labels twice to verify the caching behavior

			lbls = GetCIDRLabels(tc.prefix)
			lblArray = lbls.LabelArray()
			assert.ElementsMatch(t, lblArray, tc.expected)
		})
	}
}

func TestCIDRLabelsCache(t *testing.T) {
	// save global config and restore it at the end of the test
	enableIPv4, enableIPv6 := option.Config.EnableIPv4, option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4, option.Config.EnableIPv6 = enableIPv4, enableIPv6
	})

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("87.151.93.239/32"), netip.MustParsePrefix("87.151.93.238/31"),
		netip.MustParsePrefix("87.151.93.236/30"), netip.MustParsePrefix("87.151.93.232/29"),
		netip.MustParsePrefix("87.151.93.224/28"), netip.MustParsePrefix("87.151.93.224/27"),
		netip.MustParsePrefix("87.151.93.192/26"), netip.MustParsePrefix("87.151.93.128/25"),
		netip.MustParsePrefix("87.151.93.0/24"), netip.MustParsePrefix("87.151.92.0/23"),
		netip.MustParsePrefix("87.151.92.0/22"), netip.MustParsePrefix("87.151.88.0/21"),
		netip.MustParsePrefix("87.151.80.0/20"), netip.MustParsePrefix("87.151.64.0/19"),
		netip.MustParsePrefix("87.151.64.0/18"), netip.MustParsePrefix("87.151.0.0/17"),
		netip.MustParsePrefix("87.151.0.0/16"), netip.MustParsePrefix("87.150.0.0/15"),
		netip.MustParsePrefix("87.148.0.0/14"), netip.MustParsePrefix("87.144.0.0/13"),
		netip.MustParsePrefix("87.144.0.0/12"), netip.MustParsePrefix("87.128.0.0/11"),
		netip.MustParsePrefix("87.128.0.0/10"), netip.MustParsePrefix("87.128.0.0/9"),
		netip.MustParsePrefix("87.0.0.0/8"), netip.MustParsePrefix("86.0.0.0/7"),
		netip.MustParsePrefix("84.0.0.0/6"), netip.MustParsePrefix("80.0.0.0/5"),
		netip.MustParsePrefix("80.0.0.0/4"), netip.MustParsePrefix("64.0.0.0/3"),
		netip.MustParsePrefix("64.0.0.0/2"), netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("0.0.0.0/0"),
	}
	cidrLabels := []string{
		"cidr:0.0.0.0/0",
		"cidr:0.0.0.0/1", "cidr:64.0.0.0/2", "cidr:64.0.0.0/3", "cidr:80.0.0.0/4",
		"cidr:80.0.0.0/5", "cidr:84.0.0.0/6", "cidr:86.0.0.0/7", "cidr:87.0.0.0/8",
		"cidr:87.128.0.0/9", "cidr:87.128.0.0/10", "cidr:87.128.0.0/11", "cidr:87.144.0.0/12",
		"cidr:87.144.0.0/13", "cidr:87.148.0.0/14", "cidr:87.150.0.0/15", "cidr:87.151.0.0/16",
		"cidr:87.151.0.0/17", "cidr:87.151.64.0/18", "cidr:87.151.64.0/19", "cidr:87.151.80.0/20",
		"cidr:87.151.88.0/21", "cidr:87.151.92.0/22", "cidr:87.151.92.0/23", "cidr:87.151.93.0/24",
		"cidr:87.151.93.128/25", "cidr:87.151.93.192/26", "cidr:87.151.93.224/27", "cidr:87.151.93.224/28",
		"cidr:87.151.93.232/29", "cidr:87.151.93.236/30", "cidr:87.151.93.238/31", "cidr:87.151.93.239/32",
	}

	// check all the labels computing them from the largest CIDR to the smaller ones.
	forward := func() {
		for i := 0; i < len(prefixes); i++ {
			lbls := GetCIDRLabels(prefixes[i])
			lblArray := lbls.LabelArray()

			var expectedLblArray LabelArray
			if prefixes[i] == prefixes[len(prefixes)-1] { // default route "0.0.0.0/0" should become "reserved:world"
				expectedLblArray = ParseLabelArray("reserved:world")
			} else {
				expectedLbls := make([]string, len(cidrLabels)-i)
				copy(expectedLbls, cidrLabels[:len(cidrLabels)-i])
				expectedLblArray = ParseLabelArray(append(expectedLbls, "reserved:world")...)
			}

			assert.ElementsMatch(t, lblArray, expectedLblArray)
		}
	}
	// check all the labels computing them from the smallest CIDR to the larger ones.
	backward := func() {
		for i := 0; i < len(prefixes); i++ {
			lbls := GetCIDRLabels(prefixes[i])
			lblArray := lbls.LabelArray()

			var expectedLblArray LabelArray
			if prefixes[i] == prefixes[len(prefixes)-1] { // default route "0.0.0.0/0" should become "reserved:world"
				expectedLblArray = ParseLabelArray("reserved:world")
			} else {
				expectedLbls := make([]string, len(cidrLabels)-i)
				copy(expectedLbls, cidrLabels[:len(cidrLabels)-i])
				expectedLblArray = ParseLabelArray(append(expectedLbls, "reserved:world")...)
			}

			assert.ElementsMatch(t, lblArray, expectedLblArray)
		}
	}

	option.Config.EnableIPv4, option.Config.EnableIPv6 = true, false

	// First, compute all the labels starting from the largest CIDR to the smaller ones.
	// This will warm up the LRU cache. Then, do it the other way around to verify that
	// the cache has been populated correctly and results are consistent.

	// clear the cache
	cidrLabelsCache, _ = simplelru.NewLRU[netip.Prefix, []Label](cidrLabelsCacheMaxSize, nil)

	forward()
	backward()

	// Now, verify that the cache is populated correctly doing the opposite.

	// clear the cache
	cidrLabelsCache, _ = simplelru.NewLRU[netip.Prefix, []Label](cidrLabelsCacheMaxSize, nil)

	backward()
	forward()
}

func TestIPStringToLabel(t *testing.T) {
	for _, tc := range []struct {
		ip      string
		label   string
		wantErr bool
	}{
		{
			ip:    "0.0.0.0/0",
			label: "cidr:0.0.0.0/0",
		},
		{
			ip:    "192.0.2.3",
			label: "cidr:192.0.2.3/32",
		},
		{
			ip:    "192.0.2.3/32",
			label: "cidr:192.0.2.3/32",
		},
		{
			ip:    "192.0.2.3/24",
			label: "cidr:192.0.2.0/24",
		},
		{
			ip:    "192.0.2.0/24",
			label: "cidr:192.0.2.0/24",
		},
		{
			ip:    "::/0",
			label: "cidr:0--0/0",
		},
		{
			ip:    "fdff::ff",
			label: "cidr:fdff--ff/128",
		},
		{
			ip:    "f00d:42::ff/128",
			label: "cidr:f00d-42--ff/128",
		},
		{
			ip:    "f00d:42::ff/96",
			label: "cidr:f00d-42--0/96",
		},
		{
			ip:      "",
			wantErr: true,
		},
		{
			ip:      "foobar",
			wantErr: true,
		},
	} {
		lbl, err := IPStringToLabel(tc.ip)
		if !tc.wantErr {
			assert.NoError(t, err)
			assert.Equal(t, lbl.String(), tc.label)
		} else {
			assert.Error(t, err)
		}
	}
}

func TestCIDRLabelsCacheHeapUsageIPv4(t *testing.T) {
	t.Skip()

	// save global config and restore it at the end of the test
	enableIPv4, enableIPv6 := option.Config.EnableIPv4, option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4, option.Config.EnableIPv6 = enableIPv4, enableIPv6
	})

	option.Config.EnableIPv4, option.Config.EnableIPv6 = true, false

	// clear the cache
	cidrLabelsCache, _ = simplelru.NewLRU[netip.Prefix, []Label](cidrLabelsCacheMaxSize, nil)

	// be sure to fill the cache
	prefixes := make([]netip.Prefix, 0, 256*256)
	octets := [4]byte{0, 0, 1, 1}
	for i := 0; i < 256*256; i++ {
		octets[0], octets[1] = byte(i/256), byte(i%256)
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(octets), 32))
	}

	var m1, m2 runtime.MemStats
	// One GC does not give precise results,
	// because concurrent sweep may be still in progress.
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for _, cidr := range prefixes {
		_ = GetCIDRLabels(cidr)
	}

	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m2)

	usage := m2.HeapAlloc - m1.HeapAlloc
	t.Logf("Memoization map heap usage: %.2f KiB", float64(usage)/1024)
}

func TestCIDRLabelsCacheHeapUsageIPv6(t *testing.T) {
	t.Skip()

	// save global config and restore it at the end of the test
	enableIPv4, enableIPv6 := option.Config.EnableIPv4, option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4, option.Config.EnableIPv6 = enableIPv4, enableIPv6
	})

	option.Config.EnableIPv4, option.Config.EnableIPv6 = true, true

	// clear the cache
	cidrLabelsCache, _ = simplelru.NewLRU[netip.Prefix, []Label](cidrLabelsCacheMaxSize, nil)

	// be sure to fill the cache
	prefixes := make([]netip.Prefix, 0, 256*256)
	octets := [16]byte{
		0x00, 0x00, 0x00, 0xd8, 0x33, 0x33, 0x44, 0x44,
		0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88,
	}
	for i := 0; i < 256*256; i++ {
		octets[15], octets[14] = byte(i/256), byte(i%256)
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(octets), 128))
	}

	var m1, m2 runtime.MemStats
	// One GC does not give precise results,
	// because concurrent sweep may be still in progress.
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for _, cidr := range prefixes {
		_ = GetCIDRLabels(cidr)
	}

	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m2)

	usage := m2.HeapAlloc - m1.HeapAlloc
	t.Logf("Memoization map heap usage: %.2f KiB", float64(usage)/1024)
}

func BenchmarkGetCIDRLabels(b *testing.B) {
	// clear the cache
	cidrLabelsCache, _ = simplelru.NewLRU[netip.Prefix, []Label](cidrLabelsCacheMaxSize, nil)

	for _, cidr := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("10.16.0.0/16"),
		netip.MustParsePrefix("192.0.2.3/32"),
		netip.MustParsePrefix("192.0.2.3/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("fdff::ff/128"),
		netip.MustParsePrefix("f00d:42::ff/128"),
		netip.MustParsePrefix("f00d:42::ff/96"),
	} {
		b.Run(cidr.String(), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = GetCIDRLabels(cidr)
			}
		})
	}
}

// This benchmarks SortedList(). We want to benchmark this specific case, as
// it is excercised by toFQDN policies.
func BenchmarkLabels_SortedListCIDRIDs(b *testing.B) {
	// clear the cache
	cidrLabelsCache, _ = simplelru.NewLRU[netip.Prefix, []Label](cidrLabelsCacheMaxSize, nil)

	lbls := GetCIDRLabels(netip.MustParsePrefix("123.123.123.123/32"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lbls.SortedList()
	}
}

func BenchmarkGetCIDRLabelsConcurrent(b *testing.B) {
	prefixes := make([]netip.Prefix, 0, 16)
	octets := [4]byte{0, 0, 1, 1}
	for i := 0; i < 16; i++ {
		octets[0], octets[1] = byte(rand.Intn(256)), byte(rand.Intn(256))
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(octets), 32))
	}

	for _, goroutines := range []int{1, 2, 4, 16, 32, 48} {
		b.Run(strconv.Itoa(goroutines), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				start := make(chan struct{})
				var wg sync.WaitGroup

				wg.Add(goroutines)
				for j := 0; j < goroutines; j++ {
					go func() {
						defer wg.Done()

						<-start

						for k := 0; k < 64; k++ {
							_ = GetCIDRLabels(prefixes[rand.Intn(len(prefixes))])
						}
					}()
				}

				b.StartTimer()
				close(start)
				wg.Wait()
			}
		})
	}
}

func BenchmarkIPStringToLabel(b *testing.B) {
	for _, ip := range []string{
		"0.0.0.0/0",
		"192.0.2.3",
		"192.0.2.3/32",
		"192.0.2.3/24",
		"192.0.2.0/24",
		"::/0",
		"fdff::ff",
		"f00d:42::ff/128",
		"f00d:42::ff/96",
	} {
		b.Run(ip, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := IPStringToLabel(ip)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestGetPrintableModel(t *testing.T) {
	assert.Equal(t,
		[]string{"k8s:foo=bar"},
		NewLabelsFromModel([]string{
			"k8s:foo=bar",
		}).GetPrintableModel(),
	)

	assert.Equal(t,
		[]string{
			"k8s:foo=bar",
			"reserved:remote-node",
		},
		NewLabelsFromModel([]string{
			"k8s:foo=bar",
			"reserved:remote-node",
		}).GetPrintableModel(),
	)

	assert.Equal(t,
		[]string{
			"k8s:foo=bar",
			"reserved:remote-node",
		},
		NewLabelsFromModel([]string{
			"k8s:foo=bar",
			"reserved:remote-node",
		}).GetPrintableModel(),
	)

	// Test multiple CIDRs, as well as other labels
	cl := NewLabelsFromModel([]string{
		"k8s:foo=bar",
		"reserved:remote-node",
	})
	cl.MergeLabels(GetCIDRLabels(netip.MustParsePrefix("10.0.0.6/32")))
	cl.MergeLabels(GetCIDRLabels(netip.MustParsePrefix("10.0.1.0/24")))
	cl.MergeLabels(GetCIDRLabels(netip.MustParsePrefix("192.168.0.0/24")))
	cl.MergeLabels(GetCIDRLabels(netip.MustParsePrefix("fc00:c111::5/128")))
	cl.MergeLabels(GetCIDRLabels(netip.MustParsePrefix("fc00:c112::0/64")))
	assert.Equal(t,
		[]string{
			"cidr:10.0.0.6/32",
			"cidr:10.0.1.0/24",
			"cidr:192.168.0.0/24",
			"cidr:fc00:c111::5/128",
			"cidr:fc00:c112::0/64",
			"k8s:foo=bar",
			"reserved:remote-node",
			"reserved:world-ipv4",
			"reserved:world-ipv6",
		},
		cl.GetPrintableModel(),
	)
}

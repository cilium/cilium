// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
)

func TestGetCIDRLabels(t *testing.T) {
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
				"cidr:192.0.2.3/32",
				"reserved:world",
			),
		},
		{
			name:       "IPv4 /24 prefix",
			enableIPv4: true,
			enableIPv6: false,
			prefix:     netip.MustParsePrefix("192.0.2.0/24"),
			expected: ParseLabelArray(
				"cidr:192.0.2.0/24",
				"reserved:world",
			),
		},
		{
			name:       "IPv4 /16 prefix",
			enableIPv4: true,
			enableIPv6: false,
			prefix:     netip.MustParsePrefix("10.0.0.0/16"),
			expected: ParseLabelArray(
				"cidr:10.0.0.0/16",
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
				"cidr:2001-db8-cafe-0-cab-4-b0b-0/112",
				"reserved:world",
			),
		},
		{
			name:       "IPv6 /128 prefix",
			enableIPv4: false,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("2001:DB8::1/128"),
			expected: ParseLabelArray(
				"cidr:2001-db8--1/128",
				"reserved:world",
			),
		},
		{
			name:       "IPv4 /32 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("192.0.2.3/32"),
			expected: ParseLabelArray(
				"cidr:192.0.2.3/32",
				"reserved:world-ipv4",
			),
		},
		{
			name:       "IPv4 /24 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("192.0.2.0/24"),
			expected: ParseLabelArray(
				"cidr:192.0.2.0/24",
				"reserved:world-ipv4",
			),
		},
		{
			name:       "IPv4 /16 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("10.0.0.0/16"),
			expected: ParseLabelArray(
				"cidr:10.0.0.0/16",
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
				"cidr:2001-db8-cafe-0-cab-4-b0b-0/112",
				"reserved:world-ipv6",
			),
		},
		{
			name:       "IPv6 /128 prefix in dual stack mode",
			enableIPv4: true,
			enableIPv6: true,
			prefix:     netip.MustParsePrefix("2001:DB8::1/128"),
			expected: ParseLabelArray(
				"cidr:2001-db8--1/128",
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
		})
	}
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
			for b.Loop() {
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
			"cidr:fc00:c112::/64",
			"k8s:foo=bar",
			"reserved:remote-node",
			"reserved:world-ipv4",
			"reserved:world-ipv6",
		},
		cl.GetPrintableModel(),
	)
}

func TestLabelToPrefix(t *testing.T) {
	for _, pfx := range []string{
		"1.1.1.1/32",
		"1.1.1.0/24",
		"2001::4/128",
		"2001::fffc/126",
		"::/0",
		"2001::/64",
		"0.0.0.0/0",
	} {
		want, err := netip.ParsePrefix(pfx)
		if err != nil {
			t.Fatalf("failed to parse prefix %s: %v", pfx, err)
		}
		want = want.Masked()

		label := maskedIPToLabel(want.Addr().String(), want.Bits())
		have, err := LabelToPrefix(label.Key)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if have != want {
			t.Fatalf("prefixes did not match: want %s, have %s, label %s", want, have, label.Key)
		}
	}
}

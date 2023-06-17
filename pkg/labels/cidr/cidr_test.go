// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"net/netip"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type CIDRLabelsSuite struct{}

var _ = Suite(&CIDRLabelsSuite{})

// TestGetCIDRLabels checks that GetCIDRLabels returns a sane set of labels for
// given CIDRs.
func (s *CIDRLabelsSuite) TestGetCIDRLabels(c *C) {
	prefix := netip.MustParsePrefix("192.0.2.3/32")
	expected := labels.ParseLabelArray(
		"cidr:0.0.0.0/0",
		"cidr:128.0.0.0/1",
		"cidr:192.0.0.0/8",
		"cidr:192.0.2.0/24",
		"cidr:192.0.2.3/32",
		"reserved:world",
	)

	lbls := GetCIDRLabels(prefix)
	lblArray := lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
	// IPs should be masked as the labels are generated
	c.Assert(lblArray.Has("cidr:192.0.2.3/24"), Equals, false)

	prefix = netip.MustParsePrefix("192.0.2.0/24")
	expected = labels.ParseLabelArray(
		"cidr:0.0.0.0/0",
		"cidr:192.0.2.0/24",
		"reserved:world",
	)

	lbls = GetCIDRLabels(prefix)
	lblArray = lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
	// CIDRs that are covered by the prefix should not be in the labels
	c.Assert(lblArray.Has("cidr.192.0.2.3/32"), Equals, false)

	// Zero-length prefix / default route should become reserved:world.
	prefix = netip.MustParsePrefix("0.0.0.0/0")
	expected = labels.ParseLabelArray(
		"reserved:world",
	)

	lbls = GetCIDRLabels(prefix)
	lblArray = lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
	c.Assert(lblArray.Has("cidr.0.0.0.0/0"), Equals, false)

	// Note that we convert the colons in IPv6 addresses into dashes when
	// translating into labels, because endpointSelectors don't support
	// colons.
	prefix = netip.MustParsePrefix("2001:DB8::1/128")
	expected = labels.ParseLabelArray(
		"cidr:0--0/0",
		"cidr:2000--0/3",
		"cidr:2001--0/16",
		"cidr:2001-d00--0/24",
		"cidr:2001-db8--0/32",
		"cidr:2001-db8--1/128",
		"reserved:world",
	)

	lbls = GetCIDRLabels(prefix)
	lblArray = lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
	// IPs should be masked as the labels are generated
	c.Assert(lblArray.Has("cidr.2001-db8--1/24"), Equals, false)
}

// TestGetCIDRLabelsInCluster checks that the cluster label is properly added
// when getting labels for CIDRs that are equal to or within the cluster range.
func (s *CIDRLabelsSuite) TestGetCIDRLabelsInCluster(c *C) {
	prefix := netip.MustParsePrefix("10.0.0.0/16")
	expected := labels.ParseLabelArray(
		"cidr:0.0.0.0/0",
		"cidr:10.0.0.0/16",
		"reserved:world",
	)
	lbls := GetCIDRLabels(prefix)
	lblArray := lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})

	// This case is firmly within the cluster range
	prefix = netip.MustParsePrefix("2001:db8:cafe::cab:4:b0b:0/112")
	expected = labels.ParseLabelArray(
		"cidr:0--0/0",
		"cidr:2001-db8-cafe--0/64",
		"cidr:2001-db8-cafe-0-cab-4--0/96",
		"cidr:2001-db8-cafe-0-cab-4-b0b-0/112",
		"reserved:world",
	)
	lbls = GetCIDRLabels(prefix)
	lblArray = lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
}

func (s *CIDRLabelsSuite) TestIPStringToLabel(c *C) {
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
			c.Assert(err, IsNil)
			c.Assert(lbl.String(), checker.DeepEquals, tc.label)
		} else {
			c.Assert(err, Not(IsNil))
		}
	}
}

func BenchmarkGetCIDRLabels(b *testing.B) {
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

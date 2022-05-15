// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package cidr

import (
	"net"
	"testing"

	. "gopkg.in/check.v1"

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
	_, cidr, err := net.ParseCIDR("192.0.2.3/32")
	c.Assert(err, IsNil)
	expected := labels.ParseLabelArray(
		"cidr:0.0.0.0/0",
		"cidr:128.0.0.0/1",
		"cidr:192.0.0.0/8",
		"cidr:192.0.2.0/24",
		"cidr:192.0.2.3/32",
		"reserved:world",
	)

	lbls := GetCIDRLabels(cidr)
	lblArray := lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
	// IPs should be masked as the labels are generated
	c.Assert(lblArray.Has("cidr:192.0.2.3/24"), Equals, false)

	_, cidr, err = net.ParseCIDR("192.0.2.0/24")
	c.Assert(err, IsNil)
	expected = labels.ParseLabelArray(
		"cidr:0.0.0.0/0",
		"cidr:192.0.2.0/24",
		"reserved:world",
	)

	lbls = GetCIDRLabels(cidr)
	lblArray = lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
	// CIDRs that are covered by the prefix should not be in the labels
	c.Assert(lblArray.Has("cidr.192.0.2.3/32"), Equals, false)

	// Zero-length prefix / default route should become reserved:world.
	_, cidr, err = net.ParseCIDR("0.0.0.0/0")
	c.Assert(err, IsNil)
	expected = labels.ParseLabelArray(
		"reserved:world",
	)

	lbls = GetCIDRLabels(cidr)
	lblArray = lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
	c.Assert(lblArray.Has("cidr.0.0.0.0/0"), Equals, false)

	// Note that we convert the colons in IPv6 addresses into dashes when
	// translating into labels, because endpointSelectors don't support
	// colons.
	_, cidr, err = net.ParseCIDR("2001:DB8::1/128")
	c.Assert(err, IsNil)
	expected = labels.ParseLabelArray(
		"cidr:0--0/0",
		"cidr:2000--0/3",
		"cidr:2001--0/16",
		"cidr:2001-d00--0/24",
		"cidr:2001-db8--0/32",
		"cidr:2001-db8--1/128",
		"reserved:world",
	)

	lbls = GetCIDRLabels(cidr)
	lblArray = lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
	// IPs should be masked as the labels are generated
	c.Assert(lblArray.Has("cidr.2001-db8--1/24"), Equals, false)
}

// TestGetCIDRLabelsInCluster checks that the cluster label is properly added
// when getting labels for CIDRs that are equal to or within the cluster range.
func (s *CIDRLabelsSuite) TestGetCIDRLabelsInCluster(c *C) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/16")
	c.Assert(err, IsNil)
	expected := labels.ParseLabelArray(
		"cidr:0.0.0.0/0",
		"cidr:10.0.0.0/16",
		"reserved:world",
	)
	lbls := GetCIDRLabels(cidr)
	lblArray := lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})

	// This case is firmly within the cluster range
	_, cidr, err = net.ParseCIDR("2001:db8:cafe::cab:4:b0b:0/112")
	c.Assert(err, IsNil)
	expected = labels.ParseLabelArray(
		"cidr:0--0/0",
		"cidr:2001-db8-cafe--0/64",
		"cidr:2001-db8-cafe-0-cab-4--0/96",
		"cidr:2001-db8-cafe-0-cab-4-b0b-0/112",
		"reserved:world",
	)
	lbls = GetCIDRLabels(cidr)
	lblArray = lbls.LabelArray()
	c.Assert(lblArray.Lacks(expected), checker.DeepEquals, labels.LabelArray{})
}

func (s *CIDRLabelsSuite) TestIPStringToLabel(c *C) {
	ipToLabels := map[string]string{
		"0.0.0.0/0":    "cidr:0.0.0.0/0",
		"192.0.2.3":    "cidr:192.0.2.3/32",
		"192.0.2.3/32": "cidr:192.0.2.3/32",
		"192.0.2.3/24": "cidr:192.0.2.0/24",
		"192.0.2.0/24": "cidr:192.0.2.0/24",
		"::/0":         "cidr:0--0/0",
		"fdff::ff":     "cidr:fdff--ff/128",
	}
	for ip, labelStr := range ipToLabels {
		lbl, err := IPStringToLabel(ip)
		c.Assert(err, IsNil)
		c.Assert(lbl.String(), checker.DeepEquals, labelStr)
	}
}

func Benchmark_maskedIPNetToLabelString(b *testing.B) {
	type input struct {
		prefix     *net.IPNet
		ones, bits int
	}
	var ins []input
	for _, cidr := range []string{
		"0.0.0.0/0",
		"10.16.0.0/16",
		"192.0.2.3/32",
		"192.0.2.3/24",
		"192.0.2.0/24",
		"::/0",
		"fdff::ff/128",
	} {
		_, c, _ := net.ParseCIDR(cidr)
		ones, bits := c.Mask.Size()
		ins = append(ins, input{
			prefix: c,
			ones:   ones,
			bits:   bits,
		})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, in := range ins {
			_ = maskedIPNetToLabelString(in.prefix, in.ones, in.bits)
		}
	}
}

func Benchmark_GetCIDRLabels(b *testing.B) {
	var cidrs []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/0",
		"10.16.0.0/16",
		"192.0.2.3/32",
		"192.0.2.3/24",
		"192.0.2.0/24",
		"::/0",
		"fdff::ff/128",
	} {
		_, c, _ := net.ParseCIDR(cidr)
		cidrs = append(cidrs, c)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range cidrs {
			_ = GetCIDRLabels(c)
		}
	}
}

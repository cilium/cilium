// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package modules

import (
	"bytes"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

const (
	modulesContent = `ebtable_nat 16384 1 - Live 0x0000000000000000
ebtable_broute 16384 1 - Live 0x0000000000000000
bridge 172032 1 ebtable_broute, Live 0x0000000000000000
ip6table_nat 16384 1 - Live 0x0000000000000000
nf_nat_ipv6 16384 1 ip6table_nat, Live 0x0000000000000000
ip6table_mangle 16384 1 - Live 0x0000000000000000
ip6table_raw 16384 1 - Live 0x0000000000000000
ip6table_security 16384 1 - Live 0x0000000000000000
iptable_nat 16384 1 - Live 0x0000000000000000
nf_nat_ipv4 16384 1 iptable_nat, Live 0x0000000000000000
iptable_mangle 16384 1 - Live 0x0000000000000000
iptable_raw 16384 1 - Live 0x0000000000000000
iptable_security 16384 1 - Live 0x0000000000000000
ebtable_filter 16384 1 - Live 0x0000000000000000
ebtables 36864 3 ebtable_nat,ebtable_broute,ebtable_filter, Live 0x0000000000000000
ip6table_filter 16384 1 - Live 0x0000000000000000
ip6_tables 28672 5 ip6table_nat,ip6table_mangle,ip6table_raw,ip6table_security,ip6table_filter, Live 0x0000000000000000
iptable_filter 16384 1 - Live 0x0000000000000000
ip_tables 28672 5 iptable_nat,iptable_mangle,iptable_raw,iptable_security,iptable_filter, Live 0x0000000000000000
x_tables 40960 23 xt_multiport,xt_nat,xt_addrtype,xt_mark,xt_comment,xt_CHECKSUM,ipt_MASQUERADE,xt_tcpudp,ip6t_rpfilter,ip6t_REJECT,ipt_REJECT,xt_conntrack,ip6table_mangle,ip6table_raw,ip6table_security,iptable_mangle,iptable_raw,iptable_security,ebtables,ip6table_filter,ip6_tables,iptable_filter,ip_tables, Live 0x0000000000000000`
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ModulesTestSuite struct{}

var _ = Suite(&ModulesTestSuite{})

func (s *ModulesTestSuite) TestInit(c *C) {
	var manager ModulesManager
	c.Assert(manager.Init(), IsNil)
}

func (s *ModulesTestSuite) TestFindModules(c *C) {
	manager := &ModulesManager{
		modulesList: []string{
			"ip6_tables",
			"ip6table_mangle",
			"ip6table_filter",
			"ip6table_security",
			"ip6table_raw",
			"ip6table_nat",
		},
	}
	testCases := []struct {
		modulesToFind []string
		isSubset      bool
		expectedDiff  []string
	}{
		{
			modulesToFind: []string{
				"ip6_tables",
				"ip6table_mangle",
				"ip6table_filter",
				"ip6table_security",
				"ip6table_raw",
				"ip6table_nat",
			},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			modulesToFind: []string{
				"ip6_tables",
				"ip6table_mangle",
				"ip6table_raw",
			},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			modulesToFind: []string{
				"ip6_tables",
				"ip6table_mangle",
				"ip6table_raw",
				"foo_module",
			},
			isSubset:     false,
			expectedDiff: []string{"foo_module"},
		},
		{
			modulesToFind: []string{
				"foo_module",
				"bar_module",
			},
			isSubset:     false,
			expectedDiff: []string{"foo_module", "bar_module"},
		},
	}
	for _, tc := range testCases {
		found, diff := manager.FindModules(tc.modulesToFind...)
		c.Assert(found, Equals, tc.isSubset)
		c.Assert(diff, checker.DeepEquals, tc.expectedDiff)
	}
}

func (s *ModulesTestSuite) TestParseModuleFile(c *C) {
	expectedLength := 20
	expectedModules := []string{
		"ebtable_nat",
		"ebtable_broute",
		"bridge",
		"ip6table_nat",
		"nf_nat_ipv6",
		"ip6table_mangle",
		"ip6table_raw",
		"ip6table_security",
		"iptable_nat",
		"nf_nat_ipv4",
		"iptable_mangle",
		"iptable_raw",
		"iptable_security",
		"ebtable_filter",
		"ebtables",
		"ip6table_filter",
		"ip6_tables",
		"iptable_filter",
		"ip_tables",
		"x_tables",
	}

	r := bytes.NewBuffer([]byte(modulesContent))
	moduleInfos, err := parseModulesFile(r)
	c.Assert(err, IsNil)
	c.Assert(moduleInfos, HasLen, expectedLength)
	c.Assert(moduleInfos, checker.DeepEquals, expectedModules)
}

func (s *ModulesTestSuite) TestListModules(c *C) {
	_, err := listModules()
	c.Assert(err, IsNil)
}

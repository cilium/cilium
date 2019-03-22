// Copyright 2019 Authors of Cilium
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

// +build !privileged_tests

package modules

import (
	"bytes"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
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
	manager := &ModulesManager{}
	c.Assert(manager.modulesMap, IsNil)
	err := manager.Init()
	c.Assert(err, IsNil)
	c.Assert(manager.modulesMap, NotNil)
}

func (s *ModulesTestSuite) TestFindModule(c *C) {
	manager := &ModulesManager{
		modulesMap: []*ModuleInfo{
			{
				Name: "ip6_tables",
				Dependencies: []string{
					"ip6table_mangle",
					"ip6table_filter",
					"ip6table_security",
					"ip6table_raw",
					"ip6table_nat",
				},
			},
		},
	}
	testCasesTrue := []bool{
		manager.FindModule(
			"ip6_tables",
			"ip6table_mangle",
			"ip6table_filter",
			"ip6table_security",
			"ip6table_raw",
			"ip6table_nat",
		),
		manager.FindModule(
			"ip6_tables",
			"ip6table_mangle",
			"ip6table_raw",
		),
	}
	testCasesFalse := []bool{
		manager.FindModule(
			"ip6_tables",
			"ip6table_mangle",
			"ip6table_raw",
			"foo_dependency",
		),
		manager.FindModule(
			"foo_module",
			"foo_dependency",
		),
	}
	for _, found := range testCasesTrue {
		c.Assert(found, Equals, true)
	}
	for _, found := range testCasesFalse {
		c.Assert(found, Equals, false)
	}
}

func (s *ModulesTestSuite) TestParseModuleFile(c *C) {
	expectedLength := 20
	expectedModuleInfos := []*ModuleInfo{
		{
			Name:         "ebtable_nat",
			Dependencies: nil,
		},
		{
			Name:         "ebtable_broute",
			Dependencies: nil,
		},
		{
			Name:         "bridge",
			Dependencies: []string{"ebtable_broute"},
		},
		{
			Name:         "ip6table_nat",
			Dependencies: nil,
		},
		{
			Name:         "nf_nat_ipv6",
			Dependencies: []string{"ip6table_nat"},
		},
		{
			Name:         "ip6table_mangle",
			Dependencies: nil,
		},
		{
			Name:         "ip6table_raw",
			Dependencies: nil,
		},
		{
			Name:         "ip6table_security",
			Dependencies: nil,
		},
		{
			Name:         "iptable_nat",
			Dependencies: nil,
		},
		{
			Name:         "nf_nat_ipv4",
			Dependencies: []string{"iptable_nat"},
		},
		{
			Name:         "iptable_mangle",
			Dependencies: nil,
		},
		{
			Name:         "iptable_raw",
			Dependencies: nil,
		},
		{
			Name:         "iptable_security",
			Dependencies: nil,
		},
		{
			Name:         "ebtable_filter",
			Dependencies: nil,
		},
		{
			Name: "ebtables",
			Dependencies: []string{
				"ebtable_nat",
				"ebtable_broute",
				"ebtable_filter",
			},
		},
		{
			Name:         "ip6table_filter",
			Dependencies: nil,
		},
		{
			Name: "ip6_tables",
			Dependencies: []string{
				"ip6table_nat",
				"ip6table_mangle",
				"ip6table_raw",
				"ip6table_security",
				"ip6table_filter",
			},
		},
		{
			Name:         "iptable_filter",
			Dependencies: nil,
		},
		{
			Name: "ip_tables",
			Dependencies: []string{
				"iptable_nat",
				"iptable_mangle",
				"iptable_raw",
				"iptable_security",
				"iptable_filter",
			},
		},
		{
			Name: "x_tables",
			Dependencies: []string{
				"xt_multiport",
				"xt_nat",
				"xt_addrtype",
				"xt_mark",
				"xt_comment",
				"xt_CHECKSUM",
				"ipt_MASQUERADE",
				"xt_tcpudp",
				"ip6t_rpfilter",
				"ip6t_REJECT",
				"ipt_REJECT",
				"xt_conntrack",
				"ip6table_mangle",
				"ip6table_raw",
				"ip6table_security",
				"iptable_mangle",
				"iptable_raw",
				"iptable_security",
				"ebtables",
				"ip6table_filter",
				"ip6_tables",
				"iptable_filter",
				"ip_tables",
			},
		},
	}

	r := bytes.NewBuffer([]byte(modulesContent))
	moduleInfos, err := parseModulesFile(r)
	c.Assert(err, IsNil)
	c.Assert(moduleInfos, HasLen, expectedLength)
	c.Assert(moduleInfos, checker.DeepEquals, expectedModuleInfos)
}

func (s *ModulesTestSuite) TestListModules(c *C) {
	_, err := listModules()
	c.Assert(err, IsNil)
}

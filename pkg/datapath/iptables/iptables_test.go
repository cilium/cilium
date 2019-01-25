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

package iptables

import (
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type iptablesTestSuite struct{}

var _ = check.Suite(&iptablesTestSuite{})

func (s *iptablesTestSuite) TestRulesetDiff(c *check.C) {
	r1 := rule{"foo", "bar"}
	r2 := rule{"foo2", "bar2"}
	r3 := rule{"foo3", "bar3"}

	a := newRuleSet()
	a.add(tableNat, ciliumOutputChain, r1)
	a.add(tableNat, ciliumOutputChain, r2)
	a.add(tableFilter, ciliumOutputChain, r1)

	b := newRuleSet()
	b.add(tableNat, ciliumOutputChain, r1)
	b.add(tableNat, ciliumOutputChain, r2)

	removed, modified := a.diff(b)
	c.Assert(len(removed), check.Equals, 1)
	c.Assert(len(modified), check.Equals, 0)

	b.add(tableNat, ciliumOutputChain, r3)
	removed, modified = a.diff(b)
	c.Assert(len(removed), check.Equals, 1)
	c.Assert(len(modified), check.Equals, 1)
	c.Assert(modified[tableNat][ciliumOutputChain], checker.DeepEquals, rules{r1, r2, r3})
}

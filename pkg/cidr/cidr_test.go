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

package cidr

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type CidrTestSuite struct{}

var _ = check.Suite(&CidrTestSuite{})

func Test(t *testing.T) {
	check.TestingT(t)
}

func (t *CidrTestSuite) TestNilDeepCopy(c *check.C) {
	var c1 *CIDR
	c.Assert(c1.DeepCopy(), check.IsNil)
}

func (t *CidrTestSuite) TestDeepCopy(c *check.C) {
	_, ipnet, err := net.ParseCIDR("1.1.1.1/8")
	c.Assert(err, check.IsNil)
	c1 := NewCIDR(ipnet)
	c.Assert(c1, check.Not(check.IsNil))

	c2 := c1.DeepCopy()
	c.Assert(c1, checker.DeepEquals, c2)
}

func (t *CidrTestSuite) TestNewCIDRNil(c *check.C) {
	c.Assert(NewCIDR(nil), check.IsNil)
}

func (t *CidrTestSuite) TestIllegalParseCIDR(c *check.C) {
	c1, err := ParseCIDR("Illegal")
	c.Assert(c1, check.IsNil)
	c.Assert(err, check.Not(check.IsNil))
}

func (t *CidrTestSuite) TestIllegalMustParseCIDR(c *check.C) {
	defer func() {
		if r := recover(); r == nil {
			c.Errorf("MustParseCIDR did not panic on illegal CIDR")
		}
	}()
	c1 := MustParseCIDR("Illegal")
	c.Assert(c1, check.IsNil)
}

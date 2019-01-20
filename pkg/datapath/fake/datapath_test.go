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

package fake

import (
	"testing"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/node"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type fakeTestSuite struct{}

var _ = check.Suite(&fakeTestSuite{})

func (s *fakeTestSuite) TestNewDatapath(c *check.C) {
	dp := NewDatapath()
	c.Assert(dp, check.Not(check.IsNil))

	c.Assert(dp.Node().NodeAdd(node.Node{}), check.IsNil)
	c.Assert(dp.Node().NodeUpdate(node.Node{}, node.Node{}), check.IsNil)
	c.Assert(dp.Node().NodeDelete(node.Node{}), check.IsNil)
	c.Assert(dp.Node().NodeConfigurationChanged(datapath.LocalNodeConfiguration{}), check.IsNil)

	c.Assert(dp.LocalNodeAddressing().IPv6().Router(), check.Not(check.IsNil))
	c.Assert(dp.LocalNodeAddressing().IPv4().Router(), check.Not(check.IsNil))
	c.Assert(dp.LocalNodeAddressing().IPv4().AllocationCIDR(), check.Not(check.IsNil))
}

// Copyright 2020 Authors of Cilium
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

package eni

import (
	"gopkg.in/check.v1"
)

func (e *ENISuite) TestGetMaximumAllocatableIPv4(c *check.C) {
	n := &Node{}

	// With no k8sObj defined, it should return 0
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)

	// With instance-type = m5.large and first-interface-index = 0, we should be able to allocate up to 30 addresses
	n.k8sObj = newCiliumNode("node", "i-testnode", "m5.large", "eu-west-1", "test-vpc", 0, 0, 0, 0)
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 30)

	// With instance-type = m5.large and first-interface-index = 1, we should be able to allocate up to 20 addresses
	n.k8sObj = newCiliumNode("node", "i-testnode", "m5.large", "eu-west-1", "test-vpc", 1, 0, 0, 0)
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 20)

	// With instance-type = m5.large and first-interface-index = 4, we should return 0 as there is only 3 interfaces
	n.k8sObj = newCiliumNode("node", "i-testnode", "m5.large", "eu-west-1", "test-vpc", 4, 0, 0, 0)
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)

	// With instance-type = foo we should return 0
	n.k8sObj = newCiliumNode("node", "i-testnode", "foo", "eu-west-1", "test-vpc", 0, 0, 0, 0)
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package eni

import (
	"gopkg.in/check.v1"
)

func (e *ENISuite) TestGetMaximumAllocatableIPv4(c *check.C) {
	n := &Node{}

	// With no k8sObj defined, it should return 0
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)

	// With instance-type = m5.large and first-interface-index = 0, we should be able to allocate up to 3x10-3 addresses
	n.k8sObj = newCiliumNode("node", "i-testnode", "m5.large", "eu-west-1", "test-vpc", 0, 0, 0, 0)
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 27)

	// With instance-type = m5.large and first-interface-index = 1, we should be able to allocate up to 2x10-2 addresses
	n.k8sObj = newCiliumNode("node", "i-testnode", "m5.large", "eu-west-1", "test-vpc", 1, 0, 0, 0)
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 18)

	// With instance-type = m5.large and first-interface-index = 4, we should return 0 as there is only 3 interfaces
	n.k8sObj = newCiliumNode("node", "i-testnode", "m5.large", "eu-west-1", "test-vpc", 4, 0, 0, 0)
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)

	// With instance-type = foo we should return 0
	n.k8sObj = newCiliumNode("node", "i-testnode", "foo", "eu-west-1", "test-vpc", 0, 0, 0, 0)
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)
}

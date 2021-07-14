// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

// +build !privileged_tests

package source

import (
	"testing"

	. "gopkg.in/check.v1"
)

type SourceTestSuite struct{}

var _ = Suite(&SourceTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *SourceTestSuite) TestAllowOverwrite(c *C) {
	c.Assert(AllowOverwrite(Kubernetes, Kubernetes), Equals, true)
	c.Assert(AllowOverwrite(Kubernetes, CustomResource), Equals, true)
	c.Assert(AllowOverwrite(Kubernetes, KVStore), Equals, true)
	c.Assert(AllowOverwrite(Kubernetes, Local), Equals, true)
	c.Assert(AllowOverwrite(Kubernetes, Generated), Equals, false)
	c.Assert(AllowOverwrite(Kubernetes, Unspec), Equals, false)

	c.Assert(AllowOverwrite(CustomResource, CustomResource), Equals, true)
	c.Assert(AllowOverwrite(CustomResource, KVStore), Equals, true)
	c.Assert(AllowOverwrite(CustomResource, Local), Equals, true)
	c.Assert(AllowOverwrite(CustomResource, Kubernetes), Equals, false)
	c.Assert(AllowOverwrite(CustomResource, Generated), Equals, false)
	c.Assert(AllowOverwrite(CustomResource, Unspec), Equals, false)

	c.Assert(AllowOverwrite(KVStore, Kubernetes), Equals, false)
	c.Assert(AllowOverwrite(KVStore, CustomResource), Equals, false)
	c.Assert(AllowOverwrite(KVStore, KVStore), Equals, true)
	c.Assert(AllowOverwrite(KVStore, Local), Equals, true)
	c.Assert(AllowOverwrite(KVStore, Generated), Equals, false)
	c.Assert(AllowOverwrite(KVStore, Unspec), Equals, false)

	c.Assert(AllowOverwrite(Local, Kubernetes), Equals, false)
	c.Assert(AllowOverwrite(Local, CustomResource), Equals, false)
	c.Assert(AllowOverwrite(Local, KVStore), Equals, false)
	c.Assert(AllowOverwrite(Local, Generated), Equals, false)
	c.Assert(AllowOverwrite(Local, Local), Equals, true)
	c.Assert(AllowOverwrite(Local, Unspec), Equals, false)

	c.Assert(AllowOverwrite(Generated, Kubernetes), Equals, true)
	c.Assert(AllowOverwrite(Generated, CustomResource), Equals, true)
	c.Assert(AllowOverwrite(Generated, KVStore), Equals, true)
	c.Assert(AllowOverwrite(Generated, Local), Equals, true)
	c.Assert(AllowOverwrite(Generated, Generated), Equals, true)
	c.Assert(AllowOverwrite(Generated, Unspec), Equals, false)

	c.Assert(AllowOverwrite(Unspec, Kubernetes), Equals, true)
	c.Assert(AllowOverwrite(Unspec, CustomResource), Equals, true)
	c.Assert(AllowOverwrite(Unspec, KVStore), Equals, true)
	c.Assert(AllowOverwrite(Unspec, Local), Equals, true)
	c.Assert(AllowOverwrite(Unspec, Generated), Equals, true)
	c.Assert(AllowOverwrite(Unspec, Unspec), Equals, true)
}

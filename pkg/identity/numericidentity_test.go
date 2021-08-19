// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package identity

import (
	"github.com/cilium/cilium/pkg/clustermesh/types"

	. "gopkg.in/check.v1"
)

func (s *IdentityTestSuite) TestLocalIdentity(c *C) {
	localID := NumericIdentity(LocalIdentityFlag | 1)
	c.Assert(localID.HasLocalScope(), Equals, true)

	maxClusterID := NumericIdentity(types.ClusterIDMax | 1)
	c.Assert(maxClusterID.HasLocalScope(), Equals, false)

	c.Assert(ReservedIdentityWorld.HasLocalScope(), Equals, false)
}

func (s *IdentityTestSuite) TestClusterID(c *C) {
	tbl := []struct {
		identity  uint32
		clusterID int
	}{
		{
			identity:  0x000000,
			clusterID: 0,
		},
		{
			identity:  0x010000,
			clusterID: 1,
		},
		{
			identity:  0x2A0000,
			clusterID: 42,
		},
		{
			identity:  0xFF0000,
			clusterID: 255,
		},
		{ // make sure we support min/max configuration values
			identity:  types.ClusterIDMin << 16,
			clusterID: types.ClusterIDMin,
		},
		{
			identity:  types.ClusterIDMax << 16,
			clusterID: types.ClusterIDMax,
		},
	}

	for _, item := range tbl {
		c.Assert(NumericIdentity(item.identity).ClusterID(), Equals, item.clusterID)
	}
}

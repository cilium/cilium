// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

// +build !privileged_tests

package groups

import (
	. "gopkg.in/check.v1"
)

func (s *GroupsTestSuite) TestCacheWorkingCorrectly(c *C) {

	cnps := groupsCNPCache.GetAllCNP()
	c.Assert(len(cnps), Equals, 0)

	cnp := getSamplePolicy("test", "test")
	groupsCNPCache.UpdateCNP(cnp)

	cnps = groupsCNPCache.GetAllCNP()
	c.Assert(len(cnps), Equals, 1)

	groupsCNPCache.DeleteCNP(cnp)

	cnps = groupsCNPCache.GetAllCNP()
	c.Assert(len(cnps), Equals, 0)

}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	. "github.com/cilium/checkmate"
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

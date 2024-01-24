// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"testing"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/hive"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type linuxTestSuite struct{}

var _ = check.Suite(&linuxTestSuite{})

func (s *linuxTestSuite) TestNewDatapath(c *check.C) {
	var lc hive.Lifecycle = &hive.DefaultLifecycle{}
	dp := NewDatapath(DatapathParams{Lifecycle: lc}, DatapathConfiguration{})
	c.Assert(dp, check.Not(check.IsNil))
	c.Assert(dp.Node(), check.Not(check.IsNil))
}

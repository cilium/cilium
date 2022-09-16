// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/testutils"
)

type ProbesPrivTestSuite struct{}

var _ = Suite(&ProbesPrivTestSuite{})

func (s *ProbesPrivTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedCheck(c)
}

func (s *ProbesPrivTestSuite) TestSystemConfigProbes(c *C) {
	pm := NewProbeManager()
	err := pm.SystemConfigProbes()
	c.Assert(err, IsNil)
}

func (s *ProbesPrivTestSuite) TestExecuteHeaderProbes(c *C) {
	probes := ExecuteHeaderProbes()
	c.Assert(probes, NotNil)
}

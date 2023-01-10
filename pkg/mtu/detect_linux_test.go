// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

func (m *MTUSuite) TestAutoDetect(c *C) {
	testutils.PrivilegedCheck(c)

	mtu, err := autoDetect()
	c.Assert(err, IsNil)
	c.Assert(mtu, Not(Equals), 0)
}

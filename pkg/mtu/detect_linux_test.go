// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"github.com/cilium/cilium/pkg/testutils"

	. "github.com/cilium/checkmate"
)

func (m *MTUSuite) TestAutoDetect(c *C) {
	testutils.PrivilegedTest(c)

	mtu, err := autoDetect()
	c.Assert(err, IsNil)
	c.Assert(mtu, Not(Equals), 0)
}

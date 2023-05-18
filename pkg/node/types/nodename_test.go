// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"os"

	. "github.com/cilium/checkmate"
)

func (s *NodeSuite) TestHostname(c *C) {
	h, err := os.Hostname()

	// Unmodified node-name value is either os.Hostname if available or
	// "localhost" otherwise
	if err != nil {
		c.Assert(GetName(), Equals, "localhost")
	} else {
		c.Assert(GetName(), Equals, h)
	}

	newName := "foo.domain"
	SetName(newName)
	c.Assert(GetName(), Equals, newName)
}

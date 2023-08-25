// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"time"

	check "github.com/cilium/checkmate"
)

type operation int

const (
	operation1 operation = iota
	operation2
)

func (h *HelpersSuite) TestSetDelay(c *check.C) {
	d := NewDelaySimulator()
	c.Assert(d, check.Not(check.IsNil))

	d.SetDelay(operation1, time.Second)
	c.Assert(d.delays[operation1], check.Equals, time.Second)
	c.Assert(d.delays[operation2], check.Equals, time.Duration(0))
}

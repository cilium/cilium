// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !race

package rate

import "gopkg.in/check.v1"

func (b *ControllerSuite) TestStressRateLimiter(c *check.C) {
	b.testStressRateLimiter(c, 1000)
}

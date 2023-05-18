// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !race

package rate

import check "github.com/cilium/checkmate"

func (b *ControllerSuite) TestStressRateLimiter(c *check.C) {
	b.testStressRateLimiter(c, 1000)
}
